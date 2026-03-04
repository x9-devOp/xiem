#!/usr/bin/env python3
"""
XIEM blocklist generator - nahrazuje generate_blocklist.sh
Scoring model s exponencialnim decay, /24 agregaci a upstream feed integraci.

Umisteni: /usr/local/bin/generate_lists.py
Spousteni: systemd timer generate-lists.timer (kazdou minutu)
"""

import os
import sys
import logging
import socket
import re
from datetime import datetime
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
import requests
import netaddr

# ------------------------------------------------------------
# Config
# ------------------------------------------------------------

DB_DSN = os.environ.get(
    "XIEM_DB_DSN",
    "host=localhost port=5432 dbname=xiem user=xiem_writer"
)

OUTPUT_DIR = "/var/www/html/IP_LISTS"

# Scoring
DECAY_LAMBDA      = 0.05   # polocas ~14 dni
THRESHOLD         = 3.0    # minimalni skore pro zarazeni do blocklistu
SUBNET24_MIN_IPS  = 3      # pocet /32 v /24 pro agregaci na /24

# Vaha zdrojů (upstream_feeds ma vlastni vahu v DB)
WEIGHT_ESET  = 1.5
WEIGHT_AUTH  = 0.5
WEIGHT_MANUAL = 10.0

# Feed refresh
FEED_TIMEOUT_SEC  = 30
FEED_MAX_BYTES    = 10 * 1024 * 1024  # 10 MB

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("generate_lists")

# ------------------------------------------------------------
# DB
# ------------------------------------------------------------

@contextmanager
def get_db():
    conn = psycopg2.connect(DB_DSN)
    conn.autocommit = False
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def decay(age_days: float) -> float:
    import math
    return math.exp(-DECAY_LAMBDA * age_days)


def is_valid_ip(ip: str) -> bool:
    try:
        netaddr.IPAddress(ip)
        return True
    except Exception:
        return False


def is_valid_cidr(cidr: str) -> bool:
    try:
        netaddr.IPNetwork(cidr)
        return True
    except Exception:
        return False


def parse_ip_from_line(line: str) -> str | None:
    """Extrahuje prvni validni IP/CIDR ze radku feedu, ignoruje komentare."""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith(";"):
        return None
    # Odrizni inline komentare
    line = re.split(r"[\s;#]", line)[0].strip()
    if not line:
        return None
    # DShield format: "1.2.3.0\t24\t..." -> preved na CIDR
    parts = line.split("\t")
    if len(parts) >= 2 and parts[1].isdigit():
        cidr = f"{parts[0]}/{parts[1]}"
        if is_valid_cidr(cidr):
            return cidr
    if is_valid_cidr(line):
        return line
    return None

# ------------------------------------------------------------
# Upstream feed refresh
# ------------------------------------------------------------

def refresh_feeds():
    """Stahne vsechny enabled feedy a ulozi do upstream_feed_entries."""
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, nazev, url FROM upstream_feeds WHERE enabled = true AND list_type = 'ip'"
            )
            feeds = cur.fetchall()

    for feed in feeds:
        feed_id = feed["id"]
        nazev   = feed["nazev"]
        url     = feed["url"]

        log.info("Refreshing feed %s (%s)", nazev, url)
        try:
            resp = requests.get(url, timeout=FEED_TIMEOUT_SEC, stream=True)
            resp.raise_for_status()

            content = b""
            for chunk in resp.iter_content(chunk_size=65536):
                content += chunk
                if len(content) > FEED_MAX_BYTES:
                    log.warning("Feed %s exceeds max size, truncating", nazev)
                    break

            lines = content.decode("utf-8", errors="ignore").splitlines()
            entries = []
            for line in lines:
                ip = parse_ip_from_line(line)
                if ip:
                    entries.append(ip)

            with get_db() as conn:
                with conn.cursor() as cur:
                    # Smaz stare zaznamy tohoto feedu
                    cur.execute("DELETE FROM upstream_feed_entries WHERE feed_id = %s", (feed_id,))
                    # Vloz nove
                    psycopg2.extras.execute_batch(
                        cur,
                        "INSERT INTO upstream_feed_entries (feed_id, zaznam) VALUES (%s, %s)",
                        [(feed_id, e) for e in entries],
                        page_size=1000
                    )
                    cur.execute(
                        "UPDATE upstream_feeds SET posledni_refresh = now(), pocet_zaznamu = %s WHERE id = %s",
                        (len(entries), feed_id)
                    )

            log.info("Feed %s: %d entries", nazev, len(entries))

        except Exception as e:
            log.error("Feed %s refresh failed: %s", nazev, e)

# ------------------------------------------------------------
# Scoring
# ------------------------------------------------------------

def compute_scored_ips(conn) -> dict[str, float]:
    """Vrati {ipadresa: total_score} pro vsechny IP nad thresholdem."""
    scores: dict[str, float] = {}

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # ESET network blocks
        cur.execute("""
            SELECT ipadresa,
                   EXTRACT(EPOCH FROM (now() - cas_udalosti))/86400 AS age_days
            FROM eset_network_blocks
            WHERE cas_udalosti > now() - interval '120 days'
        """)
        for row in cur.fetchall():
            ip = row["ipadresa"]
            if not is_valid_ip(ip):
                continue
            scores[ip] = scores.get(ip, 0.0) + WEIGHT_ESET * decay(float(row["age_days"]))

        # Auth failures
        cur.execute("""
            SELECT ipadresa,
                   EXTRACT(EPOCH FROM (now() - (datum + cas)::timestamp))/86400 AS age_days
            FROM auth_failures
            WHERE datum IS NOT NULL AND cas IS NOT NULL
              AND datum > now()::date - interval '120 days'
        """)
        for row in cur.fetchall():
            ip = row["ipadresa"]
            if not is_valid_ip(ip):
                continue
            scores[ip] = scores.get(ip, 0.0) + WEIGHT_AUTH * decay(float(row["age_days"]))

        # Upstream feeds - kazdy feed ma vlastni vahu
        cur.execute("""
            SELECT e.zaznam, f.vaha,
                   EXTRACT(EPOCH FROM (now() - e.importtime))/86400 AS age_days
            FROM upstream_feed_entries e
            JOIN upstream_feeds f ON f.id = e.feed_id
            WHERE f.enabled = true AND f.list_type = 'ip'
        """)
        for row in cur.fetchall():
            zaznam = row["zaznam"]
            vaha   = float(row["vaha"] or 3.0)
            # Feed entries jsou cerstve (refresh), decay je min relevantni - ale zachovame konzistenci
            score_add = vaha * decay(float(row["age_days"]))
            # Pro CIDR z feedu: pridej skore vsem /32 v rozsahu (max /24 kvuli vykonu)
            try:
                net = netaddr.IPNetwork(zaznam, implicit_prefix=False)
                if net.prefixlen >= 24:
                    for ip in net:
                        ip_str = str(ip)
                        scores[ip_str] = scores.get(ip_str, 0.0) + score_add
                else:
                    # Pro velke rozsahy pridej skore na urovni CIDR (zpracujeme dale)
                    cidr_key = str(net.cidr)
                    scores[cidr_key] = scores.get(cidr_key, 0.0) + score_add
            except Exception:
                if is_valid_ip(zaznam):
                    scores[zaznam] = scores.get(zaznam, 0.0) + score_add

        # Manual IPs - block typ
        cur.execute("""
            SELECT zaznam FROM manual_ips
            WHERE enabled = true AND typ = 'block' AND list_type = 'ip'
        """)
        for row in cur.fetchall():
            zaznam = row["zaznam"]
            scores[zaznam] = scores.get(zaznam, 0.0) + WEIGHT_MANUAL

    return {ip: s for ip, s in scores.items() if s >= THRESHOLD}


def compute_excludes(conn) -> netaddr.IPSet:
    """Vrati IPSet vsech globalnich excludes (manual_ips typ=exclude)."""
    excludes = []
    with conn.cursor() as cur:
        cur.execute("""
            SELECT zaznam FROM manual_ips
            WHERE enabled = true AND typ = 'exclude' AND list_type = 'ip'
        """)
        for row in cur.fetchall():
            try:
                excludes.append(netaddr.IPNetwork(row[0], implicit_prefix=False))
            except Exception:
                pass
    return netaddr.IPSet(excludes)


def aggregate_to_blocklist(scored: dict[str, float], excludes: netaddr.IPSet) -> list[str]:
    """
    1. Vyrad excludes
    2. Agreguj /32 do /24 pokud >= SUBNET24_MIN_IPS ze stejneho bloku
    3. Vrat serazeny seznam CIDR stringu
    """
    # Rozdel na /32 IP a jiz-CIDR zaznamy
    ip_scores: dict[str, float] = {}
    cidr_entries: list[str] = []

    for entry, score in scored.items():
        try:
            net = netaddr.IPNetwork(entry, implicit_prefix=False)
            if net.prefixlen == 32 or "/" not in entry:
                ip_str = str(net.ip)
                if netaddr.IPAddress(ip_str) not in excludes:
                    ip_scores[ip_str] = score
            else:
                cidr_entries.append(str(net.cidr))
        except Exception:
            if is_valid_ip(entry) and netaddr.IPAddress(entry) not in excludes:
                ip_scores[entry] = score

    # /24 agregace
    subnet24: dict[str, list[str]] = {}
    for ip in ip_scores:
        try:
            net24 = str(netaddr.IPNetwork(f"{ip}/24", implicit_prefix=False).network) + "/24"
            subnet24.setdefault(net24, []).append(ip)
        except Exception:
            pass

    result_cidrs: list[str] = []
    absorbed: set[str] = set()

    for subnet, ips in subnet24.items():
        if len(ips) >= SUBNET24_MIN_IPS:
            result_cidrs.append(subnet)
            absorbed.update(ips)

    for ip in ip_scores:
        if ip not in absorbed:
            result_cidrs.append(f"{ip}/32")

    # Pridej CIDR z feedu (velke rozsahy)
    result_cidrs.extend(cidr_entries)

    # Deduplikace a merge
    try:
        merged = netaddr.cidr_merge([netaddr.IPNetwork(c) for c in result_cidrs])
        return sorted([str(n) for n in merged])
    except Exception as e:
        log.error("cidr_merge failed: %s", e)
        return sorted(set(result_cidrs))

# ------------------------------------------------------------
# Output file writer
# ------------------------------------------------------------

def write_output(filename: str, entries: list[str], source_desc: str):
    path = os.path.join(OUTPUT_DIR, filename)
    now  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# XIEM blocklist - {source_desc}",
        f"# Generated: {now}",
        f"# Entries: {len(entries)}",
        f"# Threshold: {THRESHOLD}, decay lambda: {DECAY_LAMBDA}",
        "",
    ] + entries + [""]

    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        f.write("\n".join(lines))
    os.replace(tmp_path, path)
    log.info("Written %s: %d entries", path, len(entries))

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    log.info("XIEM generate_lists.py starting")

    # 1. Refresh upstream feeds (jen pokud jsou stare > 55 minut)
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM upstream_feeds
                    WHERE enabled = true
                      AND list_type = 'ip'
                      AND (posledni_refresh IS NULL
                           OR posledni_refresh < now() - interval '55 minutes')
                """)
                stale_count = cur.fetchone()[0]

        if stale_count > 0:
            log.info("Refreshing %d stale feeds", stale_count)
            refresh_feeds()
        else:
            log.info("All feeds fresh, skipping refresh")

    except Exception as e:
        log.error("Feed refresh error: %s", e)

    # 2. Scoring a generovani
    try:
        with get_db() as conn:
            scored   = compute_scored_ips(conn)
            excludes = compute_excludes(conn)

        log.info("Scored IPs above threshold: %d", len(scored))

        blocklist = aggregate_to_blocklist(scored, excludes)
        log.info("Final blocklist entries: %d (%d /32, %d /24+)",
                 len(blocklist),
                 sum(1 for e in blocklist if e.endswith("/32")),
                 sum(1 for e in blocklist if not e.endswith("/32")))

        write_output("xiem_bad.txt", blocklist, "auth_failures + eset_network + upstream_feeds")

    except Exception as e:
        log.error("Generation error: %s", e)
        sys.exit(1)

    log.info("Done")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
XIEM blocklist generator
Generuje vystupni soubory podle konfigurace output_lists + output_list_sources.
Upstream feedy jsou zahrnuty pouze pokud jsou explicitne pridany jako zdroj listu.

Umisteni: /usr/local/bin/generate_lists.py
Spousteni: systemd timer generate-lists.timer (kazdou minutu)
"""

import os
import sys
import logging
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

DECAY_LAMBDA     = 0.05
THRESHOLD        = 3.0
SUBNET24_MIN_IPS = 3

WEIGHT_ESET   = 1.5
WEIGHT_AUTH   = 0.5
WEIGHT_MANUAL = 10.0

FEED_TIMEOUT_SEC = 30
FEED_MAX_BYTES   = 10 * 1024 * 1024

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
    line = line.strip()
    if not line or line.startswith("#") or line.startswith(";"):
        return None
    line = re.split(r"[\s;#]", line)[0].strip()
    if not line:
        return None
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

def refresh_stale_feeds():
    """Refreshne feedy ktere jsou stare > 55 minut."""
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, nazev, url FROM upstream_feeds
                WHERE enabled = true
                  AND list_type = 'ip'
                  AND (posledni_refresh IS NULL
                       OR posledni_refresh < now() - interval '55 minutes')
            """)
            stale = cur.fetchall()

    if not stale:
        log.info("All feeds fresh, skipping refresh")
        return

    log.info("Refreshing %d stale feeds", len(stale))
    for feed in stale:
        _refresh_feed(feed["id"], feed["nazev"], feed["url"])


def _refresh_feed(feed_id: int, nazev: str, url: str):
    log.info("Refreshing feed %s", nazev)
    try:
        resp = requests.get(url, timeout=FEED_TIMEOUT_SEC, stream=True)
        resp.raise_for_status()
        content = b""
        for chunk in resp.iter_content(chunk_size=65536):
            content += chunk
            if len(content) > FEED_MAX_BYTES:
                log.warning("Feed %s exceeds max size, truncating", nazev)
                break

        entries = []
        for line in content.decode("utf-8", errors="ignore").splitlines():
            ip = parse_ip_from_line(line)
            if ip:
                entries.append(ip)

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM upstream_feed_entries WHERE feed_id = %s", (feed_id,))
                if entries:
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
# Scoring per list
# ------------------------------------------------------------

def compute_scores_for_list(conn, sources: list) -> dict[str, float]:
    """
    Vypocita skore IP pouze ze zdrojů ktere jsou nakonfigurovany pro dany list.
    sources = list of dicts {source_type, source_id}
    """
    scores: dict[str, float] = {}

    source_types = {s["source_type"] for s in sources}
    feed_ids     = [s["source_id"] for s in sources if s["source_type"] == "upstream_feed" and s["source_id"]]

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:

        if "eset_network" in source_types:
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

        if "auth_failures" in source_types:
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

        if feed_ids:
            placeholders = ",".join(["%s"] * len(feed_ids))
            cur.execute(f"""
                SELECT e.zaznam, f.vaha,
                       EXTRACT(EPOCH FROM (now() - e.importtime))/86400 AS age_days
                FROM upstream_feed_entries e
                JOIN upstream_feeds f ON f.id = e.feed_id
                WHERE f.enabled = true
                  AND f.list_type = 'ip'
                  AND f.id IN ({placeholders})
            """, feed_ids)
            for row in cur.fetchall():
                zaznam    = row["zaznam"]
                vaha      = float(row["vaha"] or 3.0)
                score_add = vaha * decay(float(row["age_days"]))
                try:
                    net = netaddr.IPNetwork(zaznam, implicit_prefix=False)
                    if net.prefixlen >= 24:
                        for ip in net:
                            ip_str = str(ip)
                            scores[ip_str] = scores.get(ip_str, 0.0) + score_add
                    else:
                        cidr_key = str(net.cidr)
                        scores[cidr_key] = scores.get(cidr_key, 0.0) + score_add
                except Exception:
                    if is_valid_ip(zaznam):
                        scores[zaznam] = scores.get(zaznam, 0.0) + score_add

        if "manual" in source_types:
            cur.execute("""
                SELECT zaznam FROM manual_ips
                WHERE enabled = true AND typ = 'block' AND list_type = 'ip'
            """)
            for row in cur.fetchall():
                zaznam = row["zaznam"]
                scores[zaznam] = scores.get(zaznam, 0.0) + WEIGHT_MANUAL

    return {ip: s for ip, s in scores.items() if s >= THRESHOLD}


def compute_excludes(conn) -> netaddr.IPSet:
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
    ip_scores:    dict[str, float] = {}
    cidr_entries: list[str]        = []

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

    subnet24: dict[str, list[str]] = {}
    for ip in ip_scores:
        try:
            net24 = str(netaddr.IPNetwork(f"{ip}/24", implicit_prefix=False).network) + "/24"
            subnet24.setdefault(net24, []).append(ip)
        except Exception:
            pass

    result_cidrs: list[str] = []
    absorbed:     set[str]  = set()

    for subnet, ips in subnet24.items():
        if len(ips) >= SUBNET24_MIN_IPS:
            result_cidrs.append(subnet)
            absorbed.update(ips)

    for ip in ip_scores:
        if ip not in absorbed:
            result_cidrs.append(f"{ip}/32")

    result_cidrs.extend(cidr_entries)

    try:
        merged = netaddr.cidr_merge([netaddr.IPNetwork(c) for c in result_cidrs])
        return sorted([str(n) for n in merged])
    except Exception as e:
        log.error("cidr_merge failed: %s", e)
        return sorted(set(result_cidrs))

# ------------------------------------------------------------
# Output
# ------------------------------------------------------------

def write_output(filename: str, entries: list[str], source_desc: str):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path     = os.path.join(OUTPUT_DIR, filename)
    now      = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines    = [
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

    # 1. Refresh stale upstream feeds (vždy, nezavisle na listech)
    try:
        refresh_stale_feeds()
    except Exception as e:
        log.error("Feed refresh error: %s", e)

    # 2. Nacti vsechny enabled output listy
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, nazev, list_type
                FROM output_lists
                WHERE enabled = true AND list_type = 'ip'
                ORDER BY nazev
            """)
            lists = cur.fetchall()

    if not lists:
        log.warning("No enabled output lists found, nothing to generate")
        return

    # 3. Pro kazdy list vygeneruj soubor
    for lst in lists:
        list_id   = lst["id"]
        list_name = lst["nazev"]
        log.info("Processing list: %s", list_name)

        try:
            with get_db() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("""
                        SELECT source_type, source_id
                        FROM output_list_sources
                        WHERE list_id = %s AND enabled = true
                    """, (list_id,))
                    sources = cur.fetchall()

            if not sources:
                log.warning("List %s has no enabled sources, writing empty file", list_name)
                write_output(f"{list_name}.txt", [], f"{list_name} - no sources")
                continue

            source_desc = ", ".join(sorted({s["source_type"] for s in sources}))
            log.info("List %s sources: %s", list_name, source_desc)

            with get_db() as conn:
                scored   = compute_scores_for_list(conn, sources)
                excludes = compute_excludes(conn)

            log.info("List %s: %d IPs above threshold", list_name, len(scored))

            blocklist = aggregate_to_blocklist(scored, excludes)
            log.info("List %s: %d final entries (%d /32, %d /24+)",
                     list_name,
                     len(blocklist),
                     sum(1 for e in blocklist if e.endswith("/32")),
                     sum(1 for e in blocklist if not e.endswith("/32")))

            write_output(f"{list_name}.txt", blocklist, source_desc)

        except Exception as e:
            log.error("List %s generation failed: %s", list_name, e)

    log.info("Done")


if __name__ == "__main__":
    main()

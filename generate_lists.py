#!/usr/bin/env python3
"""
XIEM blocklist generator
Generuje vystupni soubory podle konfigurace output_lists + output_list_sources.
Vahy a parametry decay se ctou z output_list_sources.parametry (JSONB).

Umisteni: /usr/local/bin/generate_lists.py
Spousteni: systemd timer generate-lists.timer (kazdou minutu)
"""

import math
import os
import re
import sys
import logging
from datetime import datetime, timezone
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
import requests
import netaddr

# ------------------------------------------------------------
# Global defaults (pouziji se pokud parametry v DB nejsou nastaveny)
# ------------------------------------------------------------

DB_DSN = os.environ.get(
    "XIEM_DB_DSN",
    "host=localhost port=5432 dbname=xiem user=xiem_writer"
)

OUTPUT_DIR = "/var/www/html/IP_LISTS"

DEFAULT_THRESHOLD    = 3.0
DEFAULT_DECAY_LAMBDA = 0.05
DEFAULT_WINDOW_DAYS  = 120
DEFAULT_WEIGHT       = 1.0
SUBNET24_MIN_IPS     = 3
WEIGHT_MANUAL        = 10.0

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

def decay(age_days: float, lam: float) -> float:
    return math.exp(-lam * max(age_days, 0.0))


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
    # DShield format: "1.2.3.0\t24\t..."
    parts = line.split("\t")
    if len(parts) >= 2 and parts[1].isdigit():
        cidr = f"{parts[0]}/{parts[1]}"
        if is_valid_cidr(cidr):
            return cidr
    if is_valid_cidr(line):
        return line
    return None


def get_param(parametry: dict, key: str, default):
    val = parametry.get(key)
    if val is None:
        return default
    try:
        return type(default)(val)
    except Exception:
        return default


def _resolve_source(raw: dict) -> dict:
    """
    Map output_list_sources row (with optional sources JOIN) to effective
    {source_type, source_id, parametry} consumed by compute_scores_for_list.
    ols_params override src_params for scoring keys (vaha, decay_lambda, window_days).
    """
    src_type   = raw.get("src_type")
    src_params = raw.get("src_params") or {}
    ols_params = raw.get("parametry") or {}

    if src_type:
        merged = dict(src_params)
        merged.update(ols_params)
        if src_type == "upstream_http":
            return {
                "source_type": "upstream_feed",
                "source_id":   src_params.get("upstream_feed_id"),
                "parametry":   merged,
            }
        elif src_type == "agent_native":
            tbl    = src_params.get("table", "")
            legacy = "auth_failures" if tbl == "auth_failures" else "eset_network"
            return {"source_type": legacy, "source_id": None, "parametry": merged}
        elif src_type == "agent_script":
            return {"source_type": "agent_events", "source_id": None, "parametry": merged}
        elif src_type == "manual":
            # source_id carries the sources.id so compute_scores can filter manual_ips
            return {"source_type": "manual", "source_id": raw.get("source_ref_id"), "parametry": merged}

    # Legacy fallback: no source_ref_id set
    return {
        "source_type": raw["source_type"],
        "source_id":   raw["source_id"],
        "parametry":   ols_params,
    }

# ------------------------------------------------------------
# Upstream feed refresh
# ------------------------------------------------------------

def refresh_stale_feeds():
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

def compute_scores_for_list(conn, sources: list, threshold: float) -> dict[str, float]:
    """
    Vypocita skore IP ze zdrojů nakonfigurovanych pro dany list.
    Parametry (vaha, decay_lambda, window_days) se ctou z output_list_sources.parametry.
    sources = list of dicts {source_type, source_id, parametry}
    """
    scores: dict[str, float] = {}

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:

        for src in sources:
            stype  = src["source_type"]
            params = src["parametry"] or {}
            vaha   = get_param(params, "vaha",         DEFAULT_WEIGHT)
            lam    = get_param(params, "decay_lambda",  DEFAULT_DECAY_LAMBDA)
            window = get_param(params, "window_days",   DEFAULT_WINDOW_DAYS)

            if stype == "eset_network":
                cur.execute("""
                    SELECT ipadresa,
                           EXTRACT(EPOCH FROM (now() - cas_udalosti))/86400 AS age_days
                    FROM eset_network_blocks
                    WHERE cas_udalosti > now() - interval '%s days'
                """ % int(window))
                for row in cur.fetchall():
                    ip = row["ipadresa"]
                    if not is_valid_ip(ip):
                        continue
                    scores[ip] = scores.get(ip, 0.0) + vaha * decay(float(row["age_days"]), lam)

            elif stype == "auth_failures":
                cur.execute("""
                    SELECT ipadresa,
                           EXTRACT(EPOCH FROM (now() - (datum + cas)::timestamp))/86400 AS age_days
                    FROM auth_failures
                    WHERE datum IS NOT NULL AND cas IS NOT NULL
                      AND datum > now()::date - interval '%s days'
                """ % int(window))
                for row in cur.fetchall():
                    ip = row["ipadresa"]
                    if not is_valid_ip(ip):
                        continue
                    scores[ip] = scores.get(ip, 0.0) + vaha * decay(float(row["age_days"]), lam)

            elif stype == "upstream_feed" and src["source_id"]:
                feed_id = src["source_id"]
                cur.execute("""
                    SELECT e.zaznam, f.vaha AS feed_vaha,
                           EXTRACT(EPOCH FROM (now() - e.importtime))/86400 AS age_days
                    FROM upstream_feed_entries e
                    JOIN upstream_feeds f ON f.id = e.feed_id
                    WHERE f.enabled = true
                      AND f.list_type = 'ip'
                      AND f.id = %s
                """, (feed_id,))
                for row in cur.fetchall():
                    zaznam    = row["zaznam"]
                    # vaha z output_list_sources.parametry ma prednost pred upstream_feeds.vaha
                    eff_vaha  = vaha if "vaha" in params else float(row["feed_vaha"] or DEFAULT_WEIGHT)
                    score_add = eff_vaha * decay(float(row["age_days"]), lam)
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

            elif stype == "agent_events":
                module_name = params.get("module")
                ip_field    = params.get("ip_field") or "ipadresa"
                if not module_name:
                    log.warning("agent_events source missing 'module' in parametry, skipping")
                    continue
                cur.execute("""
                    SELECT payload->>%s AS ip,
                           EXTRACT(EPOCH FROM (now() - created_at))/86400 AS age_days
                    FROM agent_events
                    WHERE module = %s
                      AND created_at > now() - (%s * interval '1 day')
                      AND payload ? %s
                """, (ip_field, module_name, int(window), ip_field))
                for row in cur.fetchall():
                    ip = (row["ip"] or "").strip()
                    if not is_valid_ip(ip):
                        continue
                    scores[ip] = scores.get(ip, 0.0) + vaha * decay(float(row["age_days"]), lam)

            elif stype == "manual":
                manual_src_id = src.get("source_id")
                if manual_src_id:
                    cur.execute("""
                        SELECT zaznam FROM manual_ips
                        WHERE enabled = true AND typ = 'block' AND source_id = %s
                    """, (manual_src_id,))
                else:
                    # Legacy: entries without source_id (pre-migration)
                    cur.execute("""
                        SELECT zaznam FROM manual_ips
                        WHERE enabled = true AND typ = 'block' AND source_id IS NULL
                    """)
                for row in cur.fetchall():
                    zaznam = row["zaznam"]
                    scores[zaznam] = scores.get(zaznam, 0.0) + WEIGHT_MANUAL

    return {ip: s for ip, s in scores.items() if s >= threshold}


def compute_excludes(conn) -> netaddr.IPSet:
    excludes = []
    with conn.cursor() as cur:
        cur.execute("""
            SELECT zaznam FROM manual_ips
            WHERE enabled = true AND typ = 'exclude'
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

def write_output(filename: str, entries: list[str], source_desc: str, threshold: float):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path     = os.path.join(OUTPUT_DIR, filename)
    now      = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines    = [
        f"# XIEM blocklist - {source_desc}",
        f"# Generated: {now}",
        f"# Entries: {len(entries)}",
        f"# Threshold: {threshold}",
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

    try:
        refresh_stale_feeds()
    except Exception as e:
        log.error("Feed refresh error: %s", e)

    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, nazev, list_type, interval_min, last_generated
                FROM output_lists
                WHERE enabled = true AND list_type = 'ip'
                ORDER BY nazev
            """)
            lists = cur.fetchall()

    if not lists:
        log.warning("No enabled output lists found, nothing to generate")
        return

    for lst in lists:
        list_id   = lst["id"]
        list_name = lst["nazev"]

        # Skip if regenerated recently enough
        if lst["last_generated"] is not None:
            age_min = (datetime.now(timezone.utc) - lst["last_generated"]).total_seconds() / 60
            if age_min < lst["interval_min"]:
                log.info("List %s: skipping (generated %.1f min ago, interval %d min)",
                         list_name, age_min, lst["interval_min"])
                continue

        log.info("Processing list: %s", list_name)

        try:
            with get_db() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("""
                        SELECT ols.source_type, ols.source_id, ols.parametry,
                               ols.source_ref_id,
                               s.source_type AS src_type,
                               s.parametry   AS src_params
                        FROM output_list_sources ols
                        LEFT JOIN sources s ON ols.source_ref_id = s.id
                        WHERE ols.list_id = %s AND ols.enabled = true
                    """, (list_id,))
                    sources = [_resolve_source(r) for r in cur.fetchall()]

            if not sources:
                log.warning("List %s has no enabled sources, writing empty file", list_name)
                write_output(f"{list_name}.txt", [], f"{list_name} - no sources", DEFAULT_THRESHOLD)
                continue

            # threshold lze nastavit per-list pres parametry prvniho zdroje (nebo pouzit default)
            threshold = DEFAULT_THRESHOLD
            for src in sources:
                t = (src["parametry"] or {}).get("threshold_override")
                if t is not None:
                    try:
                        threshold = float(t)
                    except Exception:
                        pass
                    break

            source_desc = ", ".join(sorted({s["source_type"] for s in sources}))
            log.info("List %s sources: %s (threshold=%.1f)", list_name, source_desc, threshold)

            with get_db() as conn:
                scored   = compute_scores_for_list(conn, sources, threshold)
                excludes = compute_excludes(conn)

            log.info("List %s: %d IPs above threshold", list_name, len(scored))

            blocklist = aggregate_to_blocklist(scored, excludes)
            log.info("List %s: %d final entries (%d /32, %d /24+)",
                     list_name,
                     len(blocklist),
                     sum(1 for e in blocklist if e.endswith("/32")),
                     sum(1 for e in blocklist if not e.endswith("/32")))

            write_output(f"{list_name}.txt", blocklist, source_desc, threshold)

            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE output_lists SET last_generated = now() WHERE id = %s",
                        (list_id,)
                    )

        except Exception as e:
            log.error("List %s generation failed: %s", list_name, e)

    log.info("Done")


if __name__ == "__main__":
    main()

import os
import uuid
import base64
import ipaddress
import json as _json
import re
import subprocess as _subprocess
import threading as _threading
import time as _time
import requests
import psycopg2
import psycopg2.extras
from contextlib import contextmanager
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory, abort, \
                  render_template, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = os.environ.get("XIEM_SECRET_KEY", "change-me-in-production")

# ------------------------------------------------------------
# RSA command signing
# Key setup (one-time on server):
#   sudo openssl genrsa -out /etc/xiem/signing_key.pem 4096
#   sudo chmod 600 /etc/xiem/signing_key.pem
# ------------------------------------------------------------

SIGNING_KEY_PATH = os.environ.get("XIEM_SIGNING_KEY_PATH", "/etc/xiem/signing_key.pem")


def _load_signing_key():
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    with open(SIGNING_KEY_PATH, "rb") as f:
        return load_pem_private_key(f.read(), password=None)


def _get_pubkey_pem() -> str | None:
    try:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat
        )
        return _load_signing_key().public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")
    except Exception as e:
        app.logger.warning("Cannot load signing key: %s", e)
        return None


def _sign_command(cmd_id: int, command_type: str, payload: dict) -> str | None:
    """
    Signs: "{cmd_id}:{command_type}:{compact_sorted_json}"
    Uses RSA-PSS-SHA256 with salt_length=32 (matches .NET RSASignaturePadding.Pss default).
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
        key = _load_signing_key()
        canonical = f"{cmd_id}:{command_type}:{_json.dumps(payload, sort_keys=True, separators=(',', ':'))}"
        sig = key.sign(
            canonical.encode("utf-8"),
            PSS(mgf=MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256()
        )
        return base64.b64encode(sig).decode("ascii")
    except Exception as e:
        app.logger.error("Failed to sign command %d: %s", cmd_id, e)
        return None

# ------------------------------------------------------------
# DB
# ------------------------------------------------------------

DB_DSN = os.environ.get("XIEM_DB_DSN",
         "host=localhost port=5432 dbname=xiem user=xiem_writer")
AGENT_BINARY_PATH = os.environ.get("XIEM_AGENT_PATH",
                    "/var/www/flask_xiem/agent/xiem-agent.exe")


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
# Validation helpers
# ------------------------------------------------------------

FQDN_RE = re.compile(
    r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

def validate_zaznam(value, list_type):
    if list_type == "ip":
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False
    elif list_type == "fqdn":
        return bool(FQDN_RE.match(value))
    elif list_type == "url":
        return value.startswith(("http://", "https://"))
    return False

# ------------------------------------------------------------
# Agent auth
# ------------------------------------------------------------

def resolve_agent(token):
    if not token:
        return None
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, hostname, ip_adresa, group_id FROM agents "
                "WHERE token = %s AND aktivni = true", (token,)
            )
            return cur.fetchone()


def require_agent(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Agent-Token")
        agent = resolve_agent(token)
        if agent is None:
            return jsonify({"error": "unauthorized"}), 401
        return f(agent, *args, **kwargs)
    return wrapper

# ============================================================
# Agent API endpoints
# ============================================================

@app.route("/api/agent/register", methods=["POST"])
def agent_register():
    data = request.get_json(silent=True) or {}
    install_secret = data.get("install_secret", "")
    hostname       = data.get("hostname", "")
    fqdn           = data.get("fqdn", "")
    group_name     = data.get("group", "rds")
    agent_version  = data.get("agent_version", "")
    client_ip      = request.headers.get("X-Real-IP") or request.remote_addr

    if not install_secret or not hostname:
        return jsonify({"error": "install_secret and hostname required"}), 400

    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id FROM agent_install_secrets "
                "WHERE secret = %s AND aktivni = true", (install_secret,)
            )
            if cur.fetchone() is None:
                return jsonify({"error": "invalid install_secret"}), 403

            cur.execute("SELECT id FROM agent_groups WHERE nazev = %s", (group_name,))
            group_row = cur.fetchone()
            if group_row is None:
                return jsonify({"error": f"unknown group: {group_name}"}), 400

            token = str(uuid.uuid4())
            # Find existing agent: by fqdn (globally unique) or hostname+group (no-fqdn agents)
            if fqdn:
                cur.execute("SELECT id FROM agents WHERE fqdn = %s", (fqdn,))
            else:
                cur.execute(
                    "SELECT id FROM agents WHERE hostname = %s AND group_id = %s AND fqdn IS NULL",
                    (hostname, group_row["id"]))
            existing = cur.fetchone()

            if existing:
                cur.execute("""
                    UPDATE agents SET token=%s, hostname=%s, fqdn=%s, ip_adresa=%s,
                                      verze_agenta=%s, group_id=%s, aktivni=true
                    WHERE id=%s RETURNING token
                """, (token, hostname, fqdn or None, client_ip, agent_version,
                      group_row["id"], existing["id"]))
            else:
                cur.execute("""
                    INSERT INTO agents (token, hostname, fqdn, group_id, ip_adresa, verze_agenta)
                    VALUES (%s, %s, %s, %s, %s, %s) RETURNING token
                """, (token, hostname, fqdn or None, group_row["id"], client_ip, agent_version))

            row = cur.fetchone()
            if row is None:
                return jsonify({"error": "register failed"}), 500
            token = row["token"]

    return jsonify({"token": token, "config_url": "/api/agent/config",
                    "pubkey_pem": _get_pubkey_pem()}), 200


@app.route("/api/agent/pubkey", methods=["GET"])
def agent_pubkey():
    pem = _get_pubkey_pem()
    if pem is None:
        return jsonify({"error": "signing key not configured on server"}), 503
    return pem, 200, {"Content-Type": "application/x-pem-file"}


@app.route("/api/agent/config", methods=["GET"])
@require_agent
def agent_config(agent):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT modul AS name, enabled, interval_sec, module_type, parametry AS params
                FROM agent_module_config
                WHERE group_id = %s ORDER BY modul
            """, (agent["group_id"],))
            modules = [{"name": r["name"], "enabled": r["enabled"],
                        "interval_sec": r["interval_sec"], "module_type": r["module_type"],
                        "params": r["params"] or {}}
                       for r in cur.fetchall()]
    return jsonify({"modules": modules}), 200


@app.route("/api/agent/ingest", methods=["POST"])
@require_agent
def agent_ingest(agent):
    data    = request.get_json(silent=True) or {}
    module  = data.get("module", "")
    records = data.get("records", [])

    if not module or not isinstance(records, list):
        return jsonify({"error": "module and records required"}), 400

    sourceserver = f"{agent['hostname']}@{agent['ip_adresa'] or 'unknown'}"
    inserted = skipped = 0

    with get_db() as conn:
        with conn.cursor() as cur:
            if module == "eset_network":
                inserted, skipped = _ingest_eset(cur, records, sourceserver)
            elif module == "auth_failures":
                inserted, skipped = _ingest_auth(cur, records, sourceserver)
            else:
                inserted, skipped = _ingest_agent_events(cur, agent["id"], module, records)

    return jsonify({"inserted": inserted, "skipped": skipped}), 200


def _ingest_eset(cur, records, sourceserver):
    inserted = skipped = 0
    for r in records:
        if not _is_public_ip(r.get("ipadresa") or ""):
            skipped += 1
            continue
        try:
            cur.execute("""
                INSERT INTO eset_network_blocks
                    (cas_udalosti, ipadresa, akce, status, protokol, sourceserver)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT ON CONSTRAINT idx_enb_unique DO NOTHING
            """, (r.get("cas_udalosti"), r.get("ipadresa"), r.get("akce"),
                  r.get("status"), r.get("protokol"), sourceserver))
            inserted += 1 if cur.rowcount > 0 else 0
            skipped  += 0 if cur.rowcount > 0 else 1
        except Exception:
            skipped += 1
    return inserted, skipped


def _ingest_agent_events(cur, agent_id, module, records):
    inserted = skipped = 0
    for r in records:
        try:
            cur.execute("""
                INSERT INTO agent_events (agent_id, module, payload)
                VALUES (%s, %s, %s)
            """, (agent_id, module, psycopg2.extras.Json(r)))
            inserted += 1
        except Exception:
            skipped += 1
    return inserted, skipped


def _is_public_ip(ip: str) -> bool:
    """Return True only for valid, globally routable IPv4/IPv6 addresses."""
    if not ip or ip in ("-", "::1", "0.0.0.0"):
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global and not addr.is_private and not addr.is_loopback \
               and not addr.is_link_local and not addr.is_multicast \
               and not addr.is_reserved and not addr.is_unspecified
    except ValueError:
        return False


def _ingest_auth(cur, records, sourceserver):
    inserted = skipped = 0
    for r in records:
        ip = r.get("ipadresa") or ""
        if not _is_public_ip(ip):
            skipped += 1
            continue
        try:
            cur.execute("""
                INSERT INTO auth_failures
                    (datum, cas, uzivatel, accountdomain, ipadresa, pocitac,
                     logontype, mistologinu, status, substatus, proces,
                     workstation, logonprocess, authpackage, sourceserver, sourcedomain)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (r.get("datum"), r.get("cas"), r.get("uzivatel"),
                  r.get("accountdomain"), r.get("ipadresa"), r.get("pocitac"),
                  r.get("logontype"), r.get("mistologinu"), r.get("status"),
                  r.get("substatus"), r.get("proces"), r.get("workstation"),
                  r.get("logonprocess"), r.get("authpackage"),
                  sourceserver, r.get("sourcedomain")))
            inserted += 1
        except Exception:
            skipped += 1
    return inserted, skipped


@app.route("/api/agent/heartbeat", methods=["POST"])
@require_agent
def agent_heartbeat(agent):
    data    = request.get_json(silent=True) or {}
    version = data.get("version") or None
    fqdn    = data.get("fqdn")    or None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE agents
                SET posledni_kontakt = now(),
                    verze_agenta = COALESCE(%s, verze_agenta),
                    fqdn         = COALESCE(%s, fqdn)
                WHERE id = %s
            """, (version, fqdn, agent["id"]))
    return jsonify({"ok": True}), 200


@app.route("/api/agent/commands", methods=["GET"])
@require_agent
def agent_get_commands(agent):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, command_type, payload, signature
                FROM agent_commands
                WHERE status = 'pending'
                  AND (
                    agent_id  = %(aid)s
                    OR group_id  = %(gid)s
                    OR (client_id IS NOT NULL AND client_id = %(cid)s)
                    OR target_all = true
                  )
                ORDER BY created_at
            """, {"aid": agent["id"], "gid": agent["group_id"],
                  "cid": agent.get("client_id")})
            commands = cur.fetchall()

            if commands:
                ids = [c["id"] for c in commands]
                cur.execute("""
                    UPDATE agent_commands SET status = 'running'
                    WHERE id = ANY(%s)
                """, (ids,))

    return jsonify([{"id": c["id"], "command_type": c["command_type"],
                     "payload": c["payload"] or {}, "signature": c["signature"]} for c in commands]), 200


@app.route("/api/agent/commands/<int:cmd_id>/result", methods=["POST"])
@require_agent
def agent_post_command_result(agent, cmd_id):
    data     = request.get_json(silent=True) or {}
    output   = data.get("output")
    exit_code = data.get("exit_code", 0)
    error    = data.get("error")

    result_json = {"output": output, "exit_code": exit_code, "error": error,
                   "agent_hostname": agent["hostname"]}

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE agent_commands
                SET status = 'completed', executed_at = now(), result = %s
                WHERE id = %s
            """, (psycopg2.extras.Json(result_json), cmd_id))

    return jsonify({"ok": True}), 200


@app.route("/api/download/agent", methods=["GET"])
def download_agent():
    if not os.path.isfile(AGENT_BINARY_PATH):
        abort(404)
    return send_from_directory(
        os.path.dirname(AGENT_BINARY_PATH),
        os.path.basename(AGENT_BINARY_PATH),
        as_attachment=True, download_name="xiem-agent.exe",
        mimetype="application/octet-stream"
    )


@app.route("/admin/agent-binary", methods=["GET"])
def admin_agent_binary():
    info = None
    if os.path.isfile(AGENT_BINARY_PATH):
        st = os.stat(AGENT_BINARY_PATH)
        info = {
            "size":     st.st_size,
            "modified": datetime.utcfromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M UTC"),
            "path":     AGENT_BINARY_PATH,
        }
    return render_template("admin_binary.html", info=info)


@app.route("/admin/agent-binary/upload", methods=["POST"])
def admin_agent_binary_upload():
    f = request.files.get("binary")
    if not f or not f.filename:
        flash("Vyberte soubor.", "error")
        return redirect(url_for("admin_agent_binary"))
    if not f.filename.lower().endswith(".exe"):
        flash("Soubor musi mit priponu .exe", "error")
        return redirect(url_for("admin_agent_binary"))

    os.makedirs(os.path.dirname(AGENT_BINARY_PATH), exist_ok=True)
    tmp = AGENT_BINARY_PATH + ".tmp"
    try:
        f.save(tmp)
        os.replace(tmp, AGENT_BINARY_PATH)
        st = os.stat(AGENT_BINARY_PATH)
        flash(f"Binary nahrana ({st.st_size:,} B). Odeslej 'update' prikaz agentum.", "ok")
    except Exception as e:
        flash(f"Chyba pri uploadu: {e}", "error")
    return redirect(url_for("admin_agent_binary"))


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/agents/<int:agent_id>")
def agent_detail(agent_id):
    now = datetime.utcnow()
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT a.*, ag.nazev AS group_name, c.nazev AS client_name
                FROM agents a
                LEFT JOIN agent_groups ag ON a.group_id = ag.id
                LEFT JOIN clients c ON a.client_id = c.id
                WHERE a.id = %s
            """, (agent_id,))
            agent = cur.fetchone()
            if not agent:
                abort(404)

            cur.execute("""
                SELECT * FROM agent_module_config
                WHERE group_id = %s ORDER BY modul
            """, (agent["group_id"],))
            modules = cur.fetchall()

            cur.execute("""
                SELECT ac.id, ac.command_type, ac.status, ac.created_at,
                       ac.executed_at, ac.result
                FROM agent_commands ac
                WHERE ac.agent_id = %s
                   OR ac.group_id = %s
                   OR ac.target_all = true
                ORDER BY ac.created_at DESC
                LIMIT 20
            """, (agent_id, agent["group_id"]))
            commands = cur.fetchall()

            cur.execute("""
                SELECT module, payload, created_at
                FROM agent_events
                WHERE agent_id = %s
                ORDER BY created_at DESC
                LIMIT 50
            """, (agent_id,))
            events = cur.fetchall()

            cur.execute("SELECT id, nazev FROM clients ORDER BY nazev")
            clients = cur.fetchall()

            cur.execute("SELECT id, nazev FROM agent_groups ORDER BY nazev")
            groups = cur.fetchall()

    return render_template("agent_detail.html",
                           agent=agent, modules=modules, commands=commands,
                           events=events, clients=clients, groups=groups, now=now)


@app.route("/lists/<int:list_id>/interval", methods=["POST"])
def list_interval_update(list_id):
    try:
        interval_min = int(request.form.get("interval_min", 60))
        interval_min = max(1, min(1440, interval_min))
    except ValueError:
        interval_min = 60
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE output_lists SET interval_min = %s WHERE id = %s",
                        (interval_min, list_id))
    flash(f"Interval nastaven na {interval_min} min.", "ok")
    return redirect(url_for("list_detail", list_id=list_id))


@app.route("/analyze")
def analyze():
    window = request.args.get("w", "7d")
    window_map = {"24h": 1, "7d": 7, "30d": 30}
    days = window_map.get(window, 7)

    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:

            # Top 100 auth_failures
            cur.execute("""
                SELECT ipadresa,
                       COUNT(*) AS pocet,
                       MAX((datum + cas)::timestamp) AS posledni,
                       MODE() WITHIN GROUP (ORDER BY uzivatel) AS uzivatel_top,
                       MODE() WITHIN GROUP (ORDER BY sourceserver) AS server_top
                FROM auth_failures
                WHERE datum IS NOT NULL AND cas IS NOT NULL
                  AND datum > now()::date - (%s * interval '1 day')
                GROUP BY ipadresa
                ORDER BY pocet DESC
                LIMIT 1000
            """, (days,))
            top_auth = cur.fetchall()

            # Top 1000 eset_network_blocks
            cur.execute("""
                SELECT ipadresa,
                       COUNT(*) AS pocet,
                       MAX(cas_udalosti) AS posledni,
                       MODE() WITHIN GROUP (ORDER BY akce) AS akce_top,
                       MODE() WITHIN GROUP (ORDER BY sourceserver) AS server_top
                FROM eset_network_blocks
                WHERE cas_udalosti > now() - (%s * interval '1 day')
                GROUP BY ipadresa
                ORDER BY pocet DESC
                LIMIT 1000
            """, (days,))
            top_eset = cur.fetchall()

            # Top 1000 agent_events (grouped by module + ip)
            cur.execute("""
                SELECT ae.module,
                       s.nazev AS source_name,
                       s.parametry->>'ip_field' AS ip_field,
                       ae.payload->>(s.parametry->>'ip_field') AS ipadresa,
                       COUNT(*) AS pocet,
                       MAX(ae.created_at) AS posledni
                FROM agent_events ae
                JOIN sources s ON s.source_type = 'agent_script'
                  AND s.parametry->>'module' = ae.module
                WHERE ae.created_at > now() - (%s * interval '1 day')
                  AND ae.payload ? (s.parametry->>'ip_field')
                GROUP BY ae.module, s.nazev, s.parametry->>'ip_field',
                         ae.payload->>(s.parametry->>'ip_field')
                ORDER BY pocet DESC
                LIMIT 1000
            """, (days,))
            top_events = cur.fetchall()

    return render_template("analyze.html",
                           window=window,
                           top_auth=top_auth,
                           top_eset=top_eset,
                           top_events=top_events)


@app.route("/analyze/lookup")
def analyze_lookup():
    import math
    ip_str = request.args.get("ip", "").strip()
    if not ip_str:
        return render_template("analyze_lookup.html", ip=None,
                               breakdown=[], list_status=[], manual_sources=[],
                               total_score=0.0, in_exclude=False)

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        ip_str = str(ip_obj)
    except ValueError:
        flash(f"Neplatna IP adresa: {ip_str}", "error")
        return redirect(url_for("analyze_lookup"))

    DECAY_LAM = 0.05
    WINDOW    = 120

    def _decay(age_days):
        return math.exp(-DECAY_LAM * max(float(age_days), 0.0))

    breakdown      = []
    list_status    = []
    in_exclude     = False
    manual_sources = []

    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:

            # --- auth_failures ---
            cur.execute("""
                SELECT datum, cas, uzivatel, sourceserver,
                       EXTRACT(EPOCH FROM (now() - (datum + cas)::timestamp))/86400 AS age_days
                FROM auth_failures
                WHERE ipadresa = %s
                  AND datum IS NOT NULL AND cas IS NOT NULL
                  AND datum > now()::date - (%s * interval '1 day')
                ORDER BY datum DESC, cas DESC LIMIT 200
            """, (ip_str, WINDOW))
            af_rows = cur.fetchall()
            if af_rows:
                breakdown.append({
                    "name":      "auth_failures",
                    "label":     "Auth Failures (Event 4625)",
                    "score":     sum(0.5 * _decay(r["age_days"]) for r in af_rows),
                    "count":     len(af_rows),
                    "last_seen": af_rows[0].get("datum"),
                    "events":    af_rows[:30],
                    "ev_type":   "auth",
                })

            # --- eset_network_blocks ---
            cur.execute("""
                SELECT cas_udalosti, akce, protokol, sourceserver,
                       EXTRACT(EPOCH FROM (now() - cas_udalosti))/86400 AS age_days
                FROM eset_network_blocks
                WHERE ipadresa = %s
                  AND cas_udalosti > now() - (%s * interval '1 day')
                ORDER BY cas_udalosti DESC LIMIT 200
            """, (ip_str, WINDOW))
            eset_rows = cur.fetchall()
            if eset_rows:
                breakdown.append({
                    "name":      "eset_network_blocks",
                    "label":     "ESET Network Blocks",
                    "score":     sum(1.5 * _decay(r["age_days"]) for r in eset_rows),
                    "count":     len(eset_rows),
                    "last_seen": eset_rows[0].get("cas_udalosti"),
                    "events":    eset_rows[:30],
                    "ev_type":   "eset",
                })

            # --- upstream feeds ---
            cur.execute("""
                SELECT f.nazev AS feed_name, f.vaha, e.zaznam, e.importtime
                FROM upstream_feed_entries e
                JOIN upstream_feeds f ON f.id = e.feed_id
                WHERE f.enabled = true AND f.list_type = 'ip'
                  AND (e.zaznam = %s OR %s::inet << e.zaznam::inet)
                ORDER BY e.importtime DESC
            """, (ip_str, ip_str))
            feed_rows = cur.fetchall()
            if feed_rows:
                breakdown.append({
                    "name":      "upstream_feeds",
                    "label":     "Upstream Feeds",
                    "score":     sum(float(r["vaha"] or 1.0) for r in feed_rows),
                    "count":     len(feed_rows),
                    "last_seen": max((r["importtime"] for r in feed_rows if r["importtime"]),
                                    default=None),
                    "events":    feed_rows,
                    "ev_type":   "feed",
                })

            # --- agent_script sources ---
            cur.execute("""
                SELECT id, nazev, parametry, vaha_default FROM sources
                WHERE source_type = 'agent_script' AND enabled = true
            """)
            for ss in cur.fetchall():
                sp       = ss["parametry"] or {}
                module   = sp.get("module")
                ip_field = sp.get("ip_field") or "ipadresa"
                if not module:
                    continue
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur2:
                    cur2.execute("""
                        SELECT created_at, module, payload,
                               EXTRACT(EPOCH FROM (now() - created_at))/86400 AS age_days
                        FROM agent_events
                        WHERE module = %s
                          AND payload->>%s = %s
                          AND created_at > now() - (%s * interval '1 day')
                        ORDER BY created_at DESC LIMIT 100
                    """, (module, ip_field, ip_str, WINDOW))
                    ae_rows = cur2.fetchall()
                if ae_rows:
                    vaha = float(ss.get("vaha_default") or 1.0)
                    breakdown.append({
                        "name":      f"agent_script:{ss['id']}",
                        "label":     f"Script: {ss['nazev']} ({module})",
                        "score":     sum(vaha * _decay(r["age_days"]) for r in ae_rows),
                        "count":     len(ae_rows),
                        "last_seen": ae_rows[0].get("created_at"),
                        "events":    ae_rows[:20],
                        "ev_type":   "script",
                    })

            # --- manual sources ---
            cur.execute("""
                SELECT mi.id, mi.typ, mi.poznamka, mi.enabled,
                       s.id AS source_id, s.nazev AS source_name
                FROM manual_ips mi
                JOIN sources s ON s.id = mi.source_id
                WHERE mi.zaznam = %s OR %s::inet <<= mi.zaznam::inet
                ORDER BY s.nazev
            """, (ip_str, ip_str))
            manual_rows = cur.fetchall()
            if manual_rows:
                in_exclude   = any(r["typ"] == "exclude" for r in manual_rows)
                manual_score = sum(10.0 for r in manual_rows
                                   if r["typ"] == "block" and r["enabled"])
                if manual_score > 0 or in_exclude:
                    breakdown.append({
                        "name":      "manual",
                        "label":     "Manual IPs",
                        "score":     manual_score,
                        "count":     len(manual_rows),
                        "last_seen": None,
                        "events":    manual_rows,
                        "ev_type":   "manual",
                    })

            # --- per-list status ---
            cur.execute("""
                SELECT id, nazev FROM output_lists
                WHERE enabled = true AND list_type = 'ip'
                ORDER BY nazev
            """)
            lists = cur.fetchall()
            for lst in lists:
                cur.execute("""
                    SELECT ols.source_type, ols.source_id, ols.parametry,
                           ols.source_ref_id,
                           s.source_type AS src_type, s.parametry AS src_params
                    FROM output_list_sources ols
                    LEFT JOIN sources s ON ols.source_ref_id = s.id
                    WHERE ols.list_id = %s AND ols.enabled = true
                """, (lst["id"],))
                ols_rows = cur.fetchall()

                list_score = 0.0
                threshold  = 3.0
                for row in ols_rows:
                    params   = row["parametry"] or {}
                    src_type = row["src_type"] or row["source_type"]
                    vaha     = float(params.get("vaha") or 1.0)
                    lam      = float(params.get("decay_lambda") or DECAY_LAM)
                    window   = int(params.get("window_days") or WINDOW)

                    def _lscore(age_days):
                        return vaha * math.exp(-lam * max(float(age_days), 0.0))

                    if src_type in ("auth_failures", "agent_native") or \
                       row["source_type"] == "auth_failures":
                        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c2:
                            c2.execute("""
                                SELECT EXTRACT(EPOCH FROM (now() - (datum+cas)::timestamp))/86400 AS age
                                FROM auth_failures
                                WHERE ipadresa = %s AND datum IS NOT NULL AND cas IS NOT NULL
                                  AND datum > now()::date - (%s * interval '1 day')
                            """, (ip_str, window))
                            for ev in c2.fetchall():
                                list_score += _lscore(ev["age"])

                    elif src_type in ("eset_network", "eset") or \
                         row["source_type"] == "eset_network":
                        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c2:
                            c2.execute("""
                                SELECT EXTRACT(EPOCH FROM (now() - cas_udalosti))/86400 AS age
                                FROM eset_network_blocks
                                WHERE ipadresa = %s
                                  AND cas_udalosti > now() - (%s * interval '1 day')
                            """, (ip_str, window))
                            for ev in c2.fetchall():
                                list_score += _lscore(ev["age"])

                    elif src_type == "upstream_http" or row["source_type"] == "upstream_feed":
                        feed_id = (row["src_params"] or {}).get("upstream_feed_id") or row["source_id"]
                        if feed_id:
                            cur.execute("""
                                SELECT COUNT(*) AS n FROM upstream_feed_entries e
                                JOIN upstream_feeds f ON f.id = e.feed_id
                                WHERE f.id = %s AND f.enabled = true
                                  AND (e.zaznam = %s OR %s::inet << e.zaznam::inet)
                            """, (feed_id, ip_str, ip_str))
                            if cur.fetchone()["n"] > 0:
                                list_score += vaha

                    elif src_type == "agent_script" or row["source_type"] == "agent_events":
                        sp     = (row["src_params"] or {})
                        module = sp.get("module") or params.get("module")
                        ip_f   = sp.get("ip_field") or params.get("ip_field") or "ipadresa"
                        if module:
                            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c2:
                                c2.execute("""
                                    SELECT EXTRACT(EPOCH FROM (now() - created_at))/86400 AS age
                                    FROM agent_events
                                    WHERE module = %s AND payload->>%s = %s
                                      AND created_at > now() - (%s * interval '1 day')
                                """, (module, ip_f, ip_str, window))
                                for ev in c2.fetchall():
                                    list_score += _lscore(ev["age"])

                    elif src_type == "manual" or row["source_type"] == "manual":
                        mid  = row["source_ref_id"] or row["source_id"]
                        args = [ip_str]
                        q    = ("SELECT COUNT(*) AS n FROM manual_ips "
                                "WHERE typ='block' AND enabled=true AND zaznam=%s")
                        if mid:
                            q    += " AND source_id=%s"
                            args.append(mid)
                        cur.execute(q, args)
                        if cur.fetchone()["n"] > 0:
                            list_score += 10.0

                list_status.append({
                    "list_id":   lst["id"],
                    "list_name": lst["nazev"],
                    "score":     list_score,
                    "in_list":   list_score >= threshold,
                })

            # --- manual sources available for exclude ---
            cur.execute("""
                SELECT id, nazev FROM sources
                WHERE source_type = 'manual' AND enabled = true
                ORDER BY nazev
            """)
            manual_sources = cur.fetchall()

    total_score = sum(b["score"] for b in breakdown)

    return render_template(
        "analyze_lookup.html",
        ip=ip_str,
        breakdown=breakdown,
        list_status=list_status,
        manual_sources=manual_sources,
        total_score=total_score,
        in_exclude=in_exclude,
    )


@app.route("/analyze/exclude", methods=["POST"])
def analyze_exclude():
    ip_str    = request.form.get("ip", "").strip()
    source_id = request.form.get("source_id", "").strip()
    try:
        ip_str = str(ipaddress.ip_address(ip_str))
    except ValueError:
        flash(f"Neplatna IP: {ip_str}", "error")
        return redirect(url_for("analyze_lookup"))

    try:
        source_id = int(source_id)
    except (ValueError, TypeError):
        flash("Vyberte manual zdroj.", "error")
        return redirect(url_for("analyze_lookup", ip=ip_str))

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO manual_ips (zaznam, list_type, typ, poznamka, source_id)
                    VALUES (%s, 'ip', 'exclude', 'added via IP lookup', %s)
                    ON CONFLICT DO NOTHING
                """, (ip_str, source_id))
        flash(f"{ip_str} pridana jako exclude.", "ok")
    except Exception as e:
        flash(f"Chyba: {e}", "error")

    return redirect(url_for("analyze_lookup", ip=ip_str))


# ============================================================
# Management web — Dashboard
# ============================================================

@app.route("/")
def dashboard():
    now = datetime.utcnow()
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT COUNT(*) AS n FROM agents WHERE aktivni = true")
            agents_active = cur.fetchone()["n"]

            cur.execute("""
                SELECT COUNT(*) AS n FROM agents
                WHERE aktivni = true
                  AND posledni_kontakt >= now() - INTERVAL '1 hour'
            """)
            agents_online = cur.fetchone()["n"]

            cur.execute("SELECT COALESCE(SUM(pocet_zaznamu),0) AS n FROM upstream_feeds WHERE enabled = true")
            feed_ips = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM upstream_feeds WHERE enabled = true")
            feeds_active = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM manual_ips WHERE enabled = true AND typ = 'block'")
            manual_ips = cur.fetchone()["n"]

            cur.execute("""
                SELECT COUNT(*) AS n FROM auth_failures
                WHERE importtime >= now() - INTERVAL '24 hours'
            """)
            auth_24h = cur.fetchone()["n"]

            cur.execute("""
                SELECT COUNT(*) AS n FROM eset_network_blocks
                WHERE importtime >= now() - INTERVAL '24 hours'
            """)
            eset_24h = cur.fetchone()["n"]

            cur.execute("""
                SELECT a.id, a.hostname, a.fqdn, ag.nazev AS group_name, a.ip_adresa,
                       a.posledni_kontakt, a.aktivni
                FROM agents a
                LEFT JOIN agent_groups ag ON a.group_id = ag.id
                WHERE a.aktivni = true
                ORDER BY a.posledni_kontakt DESC NULLS LAST
                LIMIT 10
            """)
            recent_agents = cur.fetchall()

            cur.execute("SELECT COUNT(*) AS n FROM agent_commands WHERE status = 'pending'")
            commands_pending = cur.fetchone()["n"]

            cur.execute("""
                SELECT COUNT(*) AS n FROM agent_events
                WHERE created_at >= now() - INTERVAL '24 hours'
            """)
            events_24h = cur.fetchone()["n"]

    return render_template("dashboard.html",
        now=now, agents_active=agents_active, agents_online=agents_online,
        feed_ips=feed_ips, feeds_active=feeds_active, manual_ips=manual_ips,
        auth_24h=auth_24h, eset_24h=eset_24h, recent_agents=recent_agents,
        commands_pending=commands_pending, events_24h=events_24h)

# ============================================================
# Upstream Feeds
# ============================================================

# ============================================================
# Sources (unified source registry)
# ============================================================

_WINDOW_INTERVALS = {
    "1h":  "1 hour",
    "24h": "24 hours",
    "7d":  "7 days",
    "30d": "30 days",
}


@app.route("/sources")
def sources_list():
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM sources ORDER BY source_type, nazev")
            rows = cur.fetchall()
            cur.execute("""
                SELECT 'auth_failures' AS tbl,
                       COUNT(*) AS total,
                       COUNT(*) FILTER (WHERE importtime >= now()-'24h'::interval) AS h24,
                       MAX(importtime) AS latest
                FROM auth_failures
                UNION ALL
                SELECT 'eset_network_blocks',
                       COUNT(*),
                       COUNT(*) FILTER (WHERE importtime >= now()-'24h'::interval),
                       MAX(importtime)
                FROM eset_network_blocks
            """)
            native_stats = {r["tbl"]: r for r in cur.fetchall()}
            cur.execute("SELECT id, pocet_zaznamu, posledni_refresh FROM upstream_feeds")
            feed_stats = {r["id"]: r for r in cur.fetchall()}
            cur.execute("""
                SELECT source_id, COUNT(*) AS total
                FROM manual_ips WHERE enabled = true
                GROUP BY source_id
            """)
            manual_by_source = {r["source_id"]: r for r in cur.fetchall()}
            # Stats for agent_script sources (by module name)
            cur.execute("""
                SELECT module,
                       COUNT(*) AS total,
                       COUNT(*) FILTER (WHERE created_at >= now()-'24h'::interval) AS h24,
                       MAX(created_at) AS latest
                FROM agent_events
                GROUP BY module
            """)
            script_stats = {r["module"]: r for r in cur.fetchall()}

    sources = []
    for s in rows:
        s = dict(s)
        p = s.get("parametry") or {}
        if s["source_type"] == "agent_native":
            st = native_stats.get(p.get("table", ""), {})
            s["total_count"]   = st.get("total", 0)
            s["h24_count"]     = st.get("h24", 0)
            s["last_activity"] = st.get("latest")
        elif s["source_type"] == "upstream_http":
            st = feed_stats.get(p.get("upstream_feed_id"), {})
            s["total_count"]   = st.get("pocet_zaznamu", 0)
            s["h24_count"]     = None
            s["last_activity"] = st.get("posledni_refresh")
        elif s["source_type"] == "manual":
            st = manual_by_source.get(s["id"], {})
            s["total_count"]   = st.get("total", 0)
            s["h24_count"]     = None
            s["last_activity"] = None
        elif s["source_type"] == "agent_script":
            module = p.get("module", "")
            st = script_stats.get(module, {})
            s["total_count"]   = st.get("total", 0)
            s["h24_count"]     = st.get("h24", 0)
            s["last_activity"] = st.get("latest")
        else:
            s["total_count"]   = None
            s["h24_count"]     = None
            s["last_activity"] = None
        sources.append(s)

    return render_template("sources.html", sources=sources)


@app.route("/sources/add-feed", methods=["POST"])
def source_add_feed():
    nazev     = request.form.get("nazev", "").strip()
    url       = request.form.get("url", "").strip()
    list_type = request.form.get("list_type", "ip")
    poznamka  = request.form.get("poznamka", "").strip()

    if not nazev or not url:
        flash("Nazev a URL jsou povinne.", "error")
        return redirect(url_for("sources_list"))
    if list_type not in ("ip", "fqdn", "url"):
        list_type = "ip"

    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    INSERT INTO upstream_feeds (nazev, url, list_type, poznamka)
                    VALUES (%s, %s, %s, %s) RETURNING id, vaha
                """, (nazev, url, list_type, poznamka or None))
                feed = cur.fetchone()
                cur.execute("""
                    INSERT INTO sources (nazev, source_type, parametry, vaha_default)
                    VALUES (%s, 'upstream_http', %s, %s)
                """, (nazev, psycopg2.extras.Json({"upstream_feed_id": feed["id"]}),
                      feed["vaha"]))
        flash(f"Feed '{nazev}' pridan.", "ok")
    except psycopg2.errors.UniqueViolation:
        flash("Feed s touto URL uz existuje.", "error")
    except Exception as e:
        flash(f"Chyba: {e}", "error")
    return redirect(url_for("sources_list"))


@app.route("/sources/add-manual", methods=["POST"])
def source_add_manual():
    nazev    = request.form.get("nazev", "").strip()
    poznamka = request.form.get("poznamka", "").strip()
    if not nazev:
        flash("Nazev je povinny.", "error")
        return redirect(url_for("sources_list"))
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO sources (nazev, source_type, parametry, vaha_default)
                    VALUES (%s, 'manual', %s, 10.0)
                """, (nazev, psycopg2.extras.Json({"poznamka": poznamka} if poznamka else {})))
        flash(f"Manual zdroj '{nazev}' pridan.", "ok")
    except Exception as e:
        flash(f"Chyba: {e}", "error")
    return redirect(url_for("sources_list"))


@app.route("/sources/add-script", methods=["POST"])
def source_add_script():
    nazev    = request.form.get("nazev", "").strip()
    module   = request.form.get("module", "").strip()
    ip_field = request.form.get("ip_field", "ipadresa").strip() or "ipadresa"
    vaha     = request.form.get("vaha", "1.0").strip()

    if not nazev or not module:
        flash("Nazev a modul jsou povinne.", "error")
        return redirect(url_for("sources_list"))
    try:
        vaha_f = float(vaha)
    except ValueError:
        vaha_f = 1.0

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO sources (nazev, source_type, parametry, vaha_default)
                    VALUES (%s, 'agent_script', %s, %s)
                """, (nazev, psycopg2.extras.Json({"module": module, "ip_field": ip_field}), vaha_f))
        flash(f"Script zdroj '{nazev}' pridan.", "ok")
    except Exception as e:
        flash(f"Chyba: {e}", "error")
    return redirect(url_for("sources_list"))


@app.route("/sources/<int:source_id>/entries/add", methods=["POST"])
def source_entry_add(source_id):
    zaznam   = request.form.get("zaznam", "").strip()
    typ      = request.form.get("typ", "block")
    poznamka = request.form.get("poznamka", "").strip()

    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT source_type FROM sources WHERE id = %s", (source_id,))
            src = cur.fetchone()
    if not src or src["source_type"] != "manual":
        abort(404)
    if not zaznam:
        flash("Zaznam je povinny.", "error")
        return redirect(url_for("source_detail", source_id=source_id))
    if typ not in ("block", "exclude"):
        typ = "block"
    if not validate_zaznam(zaznam, "ip"):
        flash(f"Neplatny zaznam: {zaznam}", "error")
        return redirect(url_for("source_detail", source_id=source_id))
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO manual_ips (zaznam, list_type, typ, poznamka, source_id)
                    VALUES (%s, 'ip', %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (zaznam, typ, poznamka or None, source_id))
        flash(f"{zaznam} pridan.", "ok")
    except Exception as e:
        flash(f"Chyba: {e}", "error")
    return redirect(url_for("source_detail", source_id=source_id))


@app.route("/sources/<int:source_id>/entries/<int:entry_id>/toggle", methods=["POST"])
def source_entry_toggle(source_id, entry_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE manual_ips SET enabled = NOT enabled WHERE id = %s AND source_id = %s",
                (entry_id, source_id))
    return redirect(url_for("source_detail", source_id=source_id))


@app.route("/sources/<int:source_id>/entries/<int:entry_id>/delete", methods=["POST"])
def source_entry_delete(source_id, entry_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM manual_ips WHERE id = %s AND source_id = %s",
                        (entry_id, source_id))
    flash("Zaznam smazan.", "ok")
    return redirect(url_for("source_detail", source_id=source_id))


@app.route("/sources/<int:source_id>/entries/<int:entry_id>/note", methods=["POST"])
def source_entry_note(source_id, entry_id):
    poznamka = request.form.get("poznamka", "").strip() or None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE manual_ips SET poznamka = %s WHERE id = %s AND source_id = %s",
                        (poznamka, entry_id, source_id))
    return ("", 204)


@app.route("/sources/<int:source_id>/toggle", methods=["POST"])
def source_toggle(source_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                UPDATE sources SET enabled = NOT enabled
                WHERE id = %s RETURNING source_type, parametry, enabled
            """, (source_id,))
            row = cur.fetchone()
            if row and row["source_type"] == "upstream_http":
                fid = (row["parametry"] or {}).get("upstream_feed_id")
                if fid:
                    cur.execute("UPDATE upstream_feeds SET enabled = %s WHERE id = %s",
                                (row["enabled"], fid))
    return redirect(url_for("sources_list"))


@app.route("/sources/<int:source_id>/edit", methods=["POST"])
def source_edit(source_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM sources WHERE id = %s", (source_id,))
            src = cur.fetchone()
            if not src:
                flash("Zdroj nenalezen.", "error")
                return redirect(url_for("sources_list"))

            nazev = request.form.get("nazev", "").strip()
            if not nazev:
                flash("Nazev nesmi byt prazdny.", "error")
                return redirect(url_for("source_detail", source_id=source_id))

            try:
                vaha = float(request.form.get("vaha_default", src["vaha_default"]))
            except (ValueError, TypeError):
                vaha = src["vaha_default"]

            cur.execute(
                "UPDATE sources SET nazev = %s, vaha_default = %s WHERE id = %s",
                (nazev, vaha, source_id))

            stype = src["source_type"]
            p     = dict(src["parametry"] or {})

            if stype == "upstream_http":
                fid = p.get("upstream_feed_id")
                new_url      = request.form.get("url", "").strip()
                new_poznamka = request.form.get("poznamka", "").strip()
                if fid and new_url:
                    cur.execute("""
                        UPDATE upstream_feeds
                        SET url = %s, poznamka = %s, vaha = %s WHERE id = %s
                    """, (new_url, new_poznamka or None, vaha, fid))

            elif stype == "agent_script":
                new_module   = request.form.get("module", "").strip()
                new_ip_field = request.form.get("ip_field", "ipadresa").strip() or "ipadresa"
                if new_module:
                    p["module"]   = new_module
                    p["ip_field"] = new_ip_field
                    cur.execute("UPDATE sources SET parametry = %s WHERE id = %s",
                                (psycopg2.extras.Json(p), source_id))

    flash("Zdroj ulozen.", "ok")
    return redirect(url_for("source_detail", source_id=source_id))


@app.route("/sources/<int:source_id>/delete", methods=["POST"])
def source_delete(source_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT nazev, source_type, parametry FROM sources WHERE id = %s", (source_id,))
            src = cur.fetchone()
            if not src:
                flash("Zdroj nenalezen.", "error")
                return redirect(url_for("sources_list"))
            if src["source_type"] == "agent_native":
                flash("Systemove zdroje (agent_native) nelze smazat.", "error")
                return redirect(url_for("sources_list"))
            # For upstream_http also delete upstream_feeds row (cascades to entries)
            if src["source_type"] == "upstream_http":
                fid = (src["parametry"] or {}).get("upstream_feed_id")
                if fid:
                    cur.execute("DELETE FROM upstream_feed_entries WHERE feed_id = %s", (fid,))
                    cur.execute("DELETE FROM upstream_feeds WHERE id = %s", (fid,))
            cur.execute("DELETE FROM sources WHERE id = %s", (source_id,))
    flash(f"Zdroj '{src['nazev']}' smazan.", "ok")
    return redirect(url_for("sources_list"))


@app.route("/sources/<int:source_id>/refresh", methods=["POST"])
def source_refresh(source_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT parametry FROM sources WHERE id = %s AND source_type = 'upstream_http'",
                        (source_id,))
            row = cur.fetchone()
    if not row:
        flash("Zdroj nenalezen nebo neni upstream_http.", "error")
        return redirect(url_for("source_detail", source_id=source_id))
    fid = (row["parametry"] or {}).get("upstream_feed_id")
    if fid:
        # Delegate to existing feed_refresh logic but redirect back here
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM upstream_feeds WHERE id = %s", (fid,))
                feed = cur.fetchone()
        if feed:
            try:
                resp = requests.get(feed["url"], timeout=30)
                resp.raise_for_status()
                lines = [l.strip() for l in resp.text.splitlines()
                         if l.strip() and not l.strip().startswith("#")]
                valid = [l for l in lines if validate_zaznam(l, feed["list_type"])]
                with get_db() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM upstream_feed_entries WHERE feed_id = %s", (fid,))
                        if valid:
                            psycopg2.extras.execute_values(cur,
                                "INSERT INTO upstream_feed_entries (feed_id, zaznam) VALUES %s",
                                [(fid, v) for v in valid])
                        cur.execute("""
                            UPDATE upstream_feeds
                            SET posledni_refresh = now(), pocet_zaznamu = %s WHERE id = %s
                        """, (len(valid), fid))
                flash(f"Refresh OK: {len(valid)} zaznamu.", "ok")
            except Exception as e:
                flash(f"Refresh selhal: {e}", "error")
    return redirect(url_for("source_detail", source_id=source_id))


@app.route("/sources/<int:source_id>")
def source_detail(source_id):
    window = request.args.get("w", "24h")
    if window not in _WINDOW_INTERVALS:
        window = "24h"
    interval = _WINDOW_INTERVALS[window]

    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM sources WHERE id = %s", (source_id,))
            source = cur.fetchone()
            if source is None:
                return "Zdroj nenalezen", 404

            p = source["parametry"] or {}
            stats = {}
            top_ips = []
            recent = []
            entries = []
            feed = None

            if source["source_type"] == "agent_native":
                tbl = p.get("table", "")

                if tbl == "auth_failures":
                    cur.execute("""
                        SELECT COUNT(*) total,
                               COUNT(*) FILTER (WHERE importtime >= now()-'24h'::interval)   h24,
                               COUNT(*) FILTER (WHERE importtime >= now()-'7 days'::interval) h7d,
                               COUNT(*) FILTER (WHERE importtime >= now()-'30 days'::interval) h30d
                        FROM auth_failures
                    """)
                    stats = cur.fetchone()
                    cur.execute("""
                        SELECT ipadresa, COUNT(*) pocet, MAX(importtime) posledni
                        FROM auth_failures
                        WHERE importtime >= now() - %s::interval
                        GROUP BY ipadresa ORDER BY pocet DESC LIMIT 50
                    """, (interval,))
                    top_ips = cur.fetchall()
                    cur.execute("""
                        SELECT (datum+cas) AS ts, ipadresa, uzivatel, sourceserver
                        FROM auth_failures
                        WHERE datum IS NOT NULL AND cas IS NOT NULL
                        ORDER BY (datum+cas) DESC LIMIT 50
                    """)
                    recent = cur.fetchall()

                elif tbl == "eset_network_blocks":
                    cur.execute("""
                        SELECT COUNT(*) total,
                               COUNT(*) FILTER (WHERE importtime >= now()-'24h'::interval)   h24,
                               COUNT(*) FILTER (WHERE importtime >= now()-'7 days'::interval) h7d,
                               COUNT(*) FILTER (WHERE importtime >= now()-'30 days'::interval) h30d
                        FROM eset_network_blocks
                    """)
                    stats = cur.fetchone()
                    cur.execute("""
                        SELECT ipadresa, COUNT(*) pocet, MAX(cas_udalosti) posledni
                        FROM eset_network_blocks
                        WHERE importtime >= now() - %s::interval
                        GROUP BY ipadresa ORDER BY pocet DESC LIMIT 50
                    """, (interval,))
                    top_ips = cur.fetchall()
                    cur.execute("""
                        SELECT cas_udalosti AS ts, ipadresa, akce, protokol, sourceserver
                        FROM eset_network_blocks ORDER BY cas_udalosti DESC LIMIT 50
                    """)
                    recent = cur.fetchall()

            elif source["source_type"] == "agent_script":
                module   = p.get("module", "")
                ip_field = p.get("ip_field") or "ipadresa"
                if module:
                    cur.execute("""
                        SELECT COUNT(*) total,
                               COUNT(*) FILTER (WHERE created_at >= now()-'24h'::interval)    h24,
                               COUNT(*) FILTER (WHERE created_at >= now()-'7 days'::interval) h7d,
                               COUNT(*) FILTER (WHERE created_at >= now()-'30 days'::interval) h30d
                        FROM agent_events WHERE module = %s AND payload ? %s
                    """, (module, ip_field))
                    stats = cur.fetchone()
                    cur.execute("""
                        SELECT payload->>%s AS ipadresa,
                               COUNT(*) pocet,
                               MAX(created_at) posledni
                        FROM agent_events
                        WHERE module = %s
                          AND created_at >= now() - %s::interval
                          AND payload ? %s
                        GROUP BY 1 ORDER BY 2 DESC LIMIT 50
                    """, (ip_field, module, interval, ip_field))
                    top_ips = cur.fetchall()
                    cur.execute("""
                        SELECT ae.created_at AS ts,
                               ae.payload->>%s AS ipadresa,
                               a.hostname AS sourceserver,
                               ae.payload::text AS akce
                        FROM agent_events ae
                        LEFT JOIN agents a ON ae.agent_id = a.id
                        WHERE ae.module = %s
                        ORDER BY ae.created_at DESC LIMIT 50
                    """, (ip_field, module))
                    recent = cur.fetchall()

            elif source["source_type"] == "manual":
                cur.execute("""
                    SELECT id, zaznam, typ, poznamka, enabled
                    FROM manual_ips WHERE source_id = %s ORDER BY typ, zaznam
                """, (source_id,))
                entries = cur.fetchall()
                total   = sum(1 for e in entries if e["enabled"])
                stats   = {"total": total, "total_all": len(entries)}

            elif source["source_type"] == "upstream_http":
                fid = p.get("upstream_feed_id")
                if fid:
                    cur.execute("SELECT * FROM upstream_feeds WHERE id = %s", (fid,))
                    feed = cur.fetchone()
                    if feed:
                        stats = {"total": feed["pocet_zaznamu"],
                                 "last_refresh": feed["posledni_refresh"]}
                    cur.execute("""
                        SELECT zaznam FROM upstream_feed_entries
                        WHERE feed_id = %s ORDER BY zaznam LIMIT 500
                    """, (fid,))
                    entries = cur.fetchall()

    return render_template("source_detail.html",
                           source=source, window=window,
                           stats=stats, top_ips=top_ips,
                           recent=recent, entries=entries, feed=feed)


@app.route("/feeds")
def feeds_list():
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM upstream_feeds ORDER BY nazev")
            feeds = cur.fetchall()
    return render_template("feeds.html", feeds=feeds)


@app.route("/feeds/add", methods=["POST"])
def feed_add():
    nazev     = request.form.get("nazev", "").strip()
    url       = request.form.get("url", "").strip()
    list_type = request.form.get("list_type", "ip")
    poznamka  = request.form.get("poznamka", "").strip()

    if not nazev or not url:
        flash("Nazev a URL jsou povinne.", "error")
        return redirect(url_for("feeds_list"))

    if list_type not in ("ip", "fqdn", "url"):
        list_type = "ip"

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO upstream_feeds (nazev, url, list_type, poznamka)
                    VALUES (%s, %s, %s, %s)
                """, (nazev, url, list_type, poznamka or None))
        flash(f"Feed '{nazev}' pridan.", "ok")
    except psycopg2.errors.UniqueViolation:
        flash("Feed s touto URL uz existuje.", "error")
    except Exception as e:
        flash(f"Chyba: {e}", "error")

    return redirect(url_for("feeds_list"))


@app.route("/feeds/<int:feed_id>/toggle", methods=["POST"])
def feed_toggle(feed_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE upstream_feeds SET enabled = NOT enabled WHERE id = %s",
                (feed_id,))
    return redirect(url_for("feeds_list"))


@app.route("/feeds/<int:feed_id>/delete", methods=["POST"])
def feed_delete(feed_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM upstream_feeds WHERE id = %s", (feed_id,))
    flash("Feed smazan.", "ok")
    return redirect(url_for("feeds_list"))


@app.route("/feeds/<int:feed_id>/refresh", methods=["POST"])
def feed_refresh(feed_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM upstream_feeds WHERE id = %s", (feed_id,))
            feed = cur.fetchone()

    if not feed:
        flash("Feed nenalezen.", "error")
        return redirect(url_for("feeds_list"))

    try:
        resp = requests.get(feed["url"], timeout=30)
        resp.raise_for_status()
        lines = [l.strip() for l in resp.text.splitlines()
                 if l.strip() and not l.strip().startswith("#")]

        valid = [l for l in lines if validate_zaznam(l, feed["list_type"])]

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM upstream_feed_entries WHERE feed_id = %s",
                            (feed_id,))
                if valid:
                    psycopg2.extras.execute_values(cur,
                        "INSERT INTO upstream_feed_entries (feed_id, zaznam) VALUES %s",
                        [(feed_id, v) for v in valid]
                    )
                cur.execute("""
                    UPDATE upstream_feeds
                    SET posledni_refresh = now(), pocet_zaznamu = %s
                    WHERE id = %s
                """, (len(valid), feed_id))

        flash(f"Refresh OK: {len(valid)} zaznamu (preskoceno {len(lines)-len(valid)}).", "ok")
    except Exception as e:
        flash(f"Refresh selhal: {e}", "error")

    return redirect(url_for("feeds_list"))


@app.route("/feeds/<int:feed_id>/vaha", methods=["POST"])
def feed_vaha(feed_id):
    try:
        vaha = float(request.form.get("vaha", "3.0"))
        vaha = max(0.1, min(10.0, vaha))
    except ValueError:
        flash("Neplatna vaha.", "error")
        return redirect(url_for("feeds_list"))

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE upstream_feeds SET vaha = %s WHERE id = %s",
                        (vaha, feed_id))
    return redirect(url_for("feeds_list"))


@app.route("/feeds/<int:feed_id>/doporuceno", methods=["POST"])
def feed_doporuceno(feed_id):
    doporuceno = request.form.get("doporuceno", "inbound")
    if doporuceno not in ("inbound", "both"):
        doporuceno = "inbound"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE upstream_feeds SET doporuceno = %s WHERE id = %s",
                        (doporuceno, feed_id))
    return redirect(url_for("feeds_list"))

# ============================================================
# Manual IPs
# ============================================================

@app.route("/manual-ips")
def manual_ips_list():
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM manual_ips ORDER BY vytvoreno DESC")
            ips = cur.fetchall()
    return render_template("manual_ips.html", ips=ips)


@app.route("/manual-ips/add", methods=["POST"])
def manual_ip_add():
    zaznam    = request.form.get("zaznam", "").strip()
    list_type = request.form.get("list_type", "ip")
    typ       = request.form.get("typ", "block")
    poznamka  = request.form.get("poznamka", "").strip()

    if not zaznam:
        flash("Zaznam je povinny.", "error")
        return redirect(url_for("manual_ips_list"))

    if list_type not in ("ip", "fqdn", "url"):
        list_type = "ip"
    if typ not in ("block", "exclude"):
        typ = "block"

    if not validate_zaznam(zaznam, list_type):
        flash(f"Neplatny zaznam pro typ '{list_type}': {zaznam}", "error")
        return redirect(url_for("manual_ips_list"))

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO manual_ips (zaznam, list_type, typ, poznamka)
                    VALUES (%s, %s, %s, %s)
                """, (zaznam, list_type, typ, poznamka or None))
        flash(f"Zaznam {zaznam} pridan.", "ok")
    except Exception as e:
        flash(f"Chyba: {e}", "error")

    return redirect(url_for("manual_ips_list"))


@app.route("/manual-ips/<int:ip_id>/toggle", methods=["POST"])
def manual_ip_toggle(ip_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE manual_ips SET enabled = NOT enabled WHERE id = %s",
                        (ip_id,))
    return redirect(url_for("manual_ips_list"))


@app.route("/manual-ips/<int:ip_id>/delete", methods=["POST"])
def manual_ip_delete(ip_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM manual_ips WHERE id = %s", (ip_id,))
    flash("Zaznam smazan.", "ok")
    return redirect(url_for("manual_ips_list"))

# ============================================================
# Agents
# ============================================================

@app.route("/agents")
def agents_list():
    now = datetime.utcnow()
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT a.*, ag.nazev AS group_name, c.nazev AS client_name
                FROM agents a
                LEFT JOIN agent_groups ag ON a.group_id = ag.id
                LEFT JOIN clients c ON a.client_id = c.id
                ORDER BY a.hostname
            """)
            agents = cur.fetchall()
            cur.execute("SELECT id, nazev FROM clients ORDER BY nazev")
            clients = cur.fetchall()
    return render_template("agents.html", agents=agents, now=now, clients=clients)


@app.route("/agents/<int:agent_id>/delete", methods=["POST"])
def agent_delete(agent_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT hostname FROM agents WHERE id = %s", (agent_id,))
            row = cur.fetchone()
            if not row:
                flash("Agent nenalezen.", "error")
                return redirect(url_for("agents_list"))
            cur.execute("DELETE FROM agents WHERE id = %s", (agent_id,))
    flash(f"Agent '{row['hostname']}' smazan.", "ok")
    return redirect(url_for("agents_list"))


@app.route("/agents/<int:agent_id>/toggle", methods=["POST"])
def agent_toggle(agent_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE agents SET aktivni = NOT aktivni WHERE id = %s",
                        (agent_id,))
    return redirect(url_for("agents_list"))


@app.route("/agents/<int:agent_id>/assign-client", methods=["POST"])
def agent_assign_client(agent_id):
    client_id = request.form.get("client_id") or None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE agents SET client_id = %s WHERE id = %s",
                (int(client_id) if client_id else None, agent_id))
    return redirect(url_for("agent_detail", agent_id=agent_id))


@app.route("/agents/<int:agent_id>/assign-group", methods=["POST"])
def agent_assign_group(agent_id):
    group_id = request.form.get("group_id") or None
    if not group_id:
        return redirect(url_for("agent_detail", agent_id=agent_id))
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE agents SET group_id = %s WHERE id = %s",
                (int(group_id), agent_id))
    return redirect(url_for("agent_detail", agent_id=agent_id))

# ============================================================
# Groups & Module Config
# ============================================================

@app.route("/groups")
def groups_list():
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT ag.id, ag.nazev,
                       COUNT(a.id) AS agent_count
                FROM agent_groups ag
                LEFT JOIN agents a ON a.group_id = ag.id AND a.aktivni = true
                GROUP BY ag.id, ag.nazev
                ORDER BY ag.nazev
            """)
            groups = cur.fetchall()

            cur.execute("SELECT * FROM agent_module_config ORDER BY group_id, modul")
            all_modules = cur.fetchall()

    modules_by_group = {}
    for m in all_modules:
        modules_by_group.setdefault(m["group_id"], []).append(dict(m))

    return render_template("groups.html", groups=groups, modules_by_group=modules_by_group)


@app.route("/groups/<int:group_id>/modules/<module_name>/update", methods=["POST"])
def group_module_update(group_id, module_name):
    import json as _json
    enabled = request.form.get("enabled") == "1"
    try:
        interval_sec = int(request.form.get("interval_sec", 3600))
        interval_sec = max(60, min(86400, interval_sec))
    except ValueError:
        interval_sec = 3600
    module_type = request.form.get("module_type", "native")
    if module_type not in ("native", "powershell", "cmd"):
        module_type = "native"

    # Build parametry from script-specific fields when module_type == powershell
    parametry = None
    if module_type == "powershell":
        script      = request.form.get("script", "").strip()
        ip_field    = request.form.get("ip_field", "").strip()
        timeout_sec = request.form.get("timeout_sec", "30").strip()
        fm_raw      = request.form.get("field_mapping", "").strip()

        parametry = {}
        if script:
            parametry["script"] = script
        if ip_field:
            parametry["ip_field"] = ip_field
        try:
            parametry["timeout_sec"] = int(timeout_sec) if timeout_sec else 30
        except ValueError:
            parametry["timeout_sec"] = 30
        if fm_raw:
            try:
                parametry["field_mapping"] = _json.loads(fm_raw)
            except ValueError:
                flash("Neplatny JSON v field_mapping.", "error")
                return redirect(url_for("groups_list"))

    with get_db() as conn:
        with conn.cursor() as cur:
            if parametry is not None:
                cur.execute("""
                    UPDATE agent_module_config
                    SET enabled = %s, interval_sec = %s, module_type = %s, parametry = %s
                    WHERE group_id = %s AND modul = %s
                """, (enabled, interval_sec, module_type,
                      psycopg2.extras.Json(parametry), group_id, module_name))
            else:
                cur.execute("""
                    UPDATE agent_module_config
                    SET enabled = %s, interval_sec = %s, module_type = %s
                    WHERE group_id = %s AND modul = %s
                """, (enabled, interval_sec, module_type, group_id, module_name))
    flash(f"Modul {module_name} aktualizovan.", "ok")
    return redirect(url_for("groups_list"))

# ============================================================
# Output Lists
# ============================================================

@app.route("/lists")
def lists_list():
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT ol.*,
                       c.nazev AS client_nazev,
                       (SELECT COUNT(*) FROM output_list_sources ols
                        WHERE ols.list_id = ol.id AND ols.enabled = true) AS source_count
                FROM output_lists ol
                LEFT JOIN clients c ON ol.client_id = c.id
                ORDER BY ol.nazev
            """)
            lists = cur.fetchall()
            cur.execute("SELECT id, nazev FROM clients ORDER BY nazev")
            clients = cur.fetchall()
    return render_template("lists.html", lists=lists, clients=clients)


@app.route("/lists/add", methods=["POST"])
def list_add():
    nazev     = request.form.get("nazev", "").strip()
    list_type = request.form.get("list_type", "ip")
    resolve   = request.form.get("resolve", "0") == "1"
    client_id = request.form.get("client_id") or None
    popis     = request.form.get("popis", "").strip()

    if not nazev or not re.match(r'^[a-zA-Z0-9_\-]+$', nazev):
        flash("Neplatny nazev (jen pismena, cisla, _ a -).", "error")
        return redirect(url_for("lists_list"))

    if list_type not in ("ip", "fqdn", "url"):
        list_type = "ip"

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO output_lists (nazev, list_type, resolve, client_id, popis)
                    VALUES (%s, %s, %s, %s, %s)
                """, (nazev, list_type, resolve,
                      int(client_id) if client_id else None,
                      popis or None))
        flash(f"List '{nazev}' vytvoreno.", "ok")
    except psycopg2.errors.UniqueViolation:
        flash("List s timto nazvem uz existuje.", "error")
    except Exception as e:
        flash(f"Chyba: {e}", "error")

    return redirect(url_for("lists_list"))


@app.route("/lists/<int:list_id>/toggle", methods=["POST"])
def list_toggle(list_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE output_lists SET enabled = NOT enabled WHERE id = %s",
                        (list_id,))
    return redirect(url_for("lists_list"))


@app.route("/lists/<int:list_id>/delete", methods=["POST"])
def list_delete(list_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM output_lists WHERE id = %s", (list_id,))
    flash("List smazan.", "ok")
    return redirect(url_for("lists_list"))


_LIST_EXPLAIN_CACHE: dict[int, dict] = {}
_LIST_EXPLAIN_TTL = 3600  # 1 hour


@app.route("/lists/<int:list_id>/explain")
def list_explain(list_id):
    import anthropic as _anthropic
    cache = _LIST_EXPLAIN_CACHE.get(list_id, {})
    if cache.get("ts", 0) + _LIST_EXPLAIN_TTL > _time.time():
        return jsonify({"content": cache["content"]})

    if not ANTHROPIC_API_KEY:
        return jsonify({"error": "ANTHROPIC_API_KEY neni nastaven"}), 503

    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM output_lists WHERE id = %s", (list_id,))
            lst = cur.fetchone()
            if not lst:
                return jsonify({"error": "List nenalezen"}), 404

            cur.execute("""
                SELECT ols.source_type, ols.source_id, ols.enabled, ols.parametry,
                       uf.nazev AS feed_name, uf.vaha AS feed_vaha, uf.pocet_zaznamu AS feed_count
                FROM output_list_sources ols
                LEFT JOIN upstream_feeds uf ON ols.source_id = uf.id
                WHERE ols.list_id = %s ORDER BY ols.source_type, ols.id
            """, (list_id,))
            sources = cur.fetchall()

            cur.execute("""
                SELECT COUNT(*) AS auth_total,
                       COUNT(*) FILTER (WHERE importtime >= NOW()-INTERVAL '24h') AS auth_24h,
                       COUNT(*) FILTER (WHERE importtime >= NOW()-INTERVAL '7 days') AS auth_7d
                FROM auth_failures
            """)
            af_stats = cur.fetchone()

            cur.execute("""
                SELECT COUNT(*) AS eset_total,
                       COUNT(*) FILTER (WHERE importtime >= NOW()-INTERVAL '24h') AS eset_24h
                FROM eset_network_blocks
            """)
            eset_stats = cur.fetchone()

    # Build context for Claude
    src_lines = []
    for s in sources:
        p = s["parametry"] or {}
        if s["source_type"] == "upstream_feed":
            src_lines.append(
                f"- upstream_feed '{s['feed_name']}': {s['feed_count']} entries, "
                f"feed_vaha={s['feed_vaha']}, param_vaha={p.get('vaha','default')}, "
                f"decay_lambda={p.get('decay_lambda', 0.05)}, window_days={p.get('window_days', 120)}, "
                f"enabled={s['enabled']}"
            )
        else:
            src_lines.append(
                f"- {s['source_type']}: vaha={p.get('vaha', 'default(1.0)')}, "
                f"decay_lambda={p.get('decay_lambda', 0.05)}, "
                f"window_days={p.get('window_days', 120)}, enabled={s['enabled']}"
            )

    context = f"""
Output list: {lst['nazev']} (type={lst['list_type']}, interval_min={lst['interval_min']})
Last generated: {lst['last_generated']}
Threshold: 3.0 (default, can be overridden per source via threshold_override)

Sources:
{chr(10).join(src_lines) if src_lines else '(none)'}

Scoring formula: score(ip) = sum over sources: vaha * exp(-decay_lambda * age_days)
IP is included if score >= threshold.
/24 aggregation: if >= 3 IPs from same /24 block, aggregate to /24 CIDR.
manual_block IPs always score 10.0 (above any threshold).

Current data in DB:
- auth_failures total: {af_stats['auth_total']}, last 24h: {af_stats['auth_24h']}, last 7d: {af_stats['auth_7d']}
- eset_network_blocks total: {eset_stats['eset_total']}, last 24h: {eset_stats['eset_24h']}

DEFAULT_WEIGHT constant in code = 1.0 (used when 'vaha' not set in parametry)
"""

    try:
        client = _anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        msg = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1200,
            system=(
                "You are a security engineer reviewing a blocklist generation algorithm "
                "for an MSP company managing ~100 Windows servers. "
                "Explain the algorithm in Czech in plain, human-readable language. "
                "Cover: what the list does, how scoring works in practice "
                "(give concrete examples: 'IP s 3 dnesnimi auth failures dostane score X'), "
                "how long an IP stays in the list (half-life), "
                "and any potential issues or improvements. "
                "Use Markdown. Be concise and practical."
            ),
            messages=[{"role": "user", "content": context}],
        )
        content = msg.content[0].text
        _LIST_EXPLAIN_CACHE[list_id] = {"ts": _time.time(), "content": content}
        return jsonify({"content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/lists/<int:list_id>")
def list_detail(list_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM output_lists WHERE id = %s", (list_id,))
            lst = cur.fetchone()
            if not lst:
                abort(404)

            cur.execute("""
                SELECT ols.*, uf.nazev AS feed_nazev,
                       uf.pocet_zaznamu AS feed_pocet,
                       uf.vaha AS feed_vaha,
                       uf.doporuceno AS feed_doporuceno
                FROM output_list_sources ols
                LEFT JOIN upstream_feeds uf ON ols.source_id = uf.id
                WHERE ols.list_id = %s
                ORDER BY ols.source_type, ols.id
            """, (list_id,))
            sources = cur.fetchall()

            cur.execute("""
                SELECT id, nazev, source_type, parametry, vaha_default
                FROM sources WHERE enabled = true
                ORDER BY source_type, nazev
            """)
            all_sources = cur.fetchall()

    return render_template("list_detail.html", lst=lst, sources=sources, all_sources=all_sources)


@app.route("/lists/<int:list_id>/sources/add", methods=["POST"])
def list_source_add(list_id):
    source_ref_id = request.form.get("source_ref_id") or None

    if not source_ref_id:
        flash("Vyberte zdroj.", "error")
        return redirect(url_for("list_detail", list_id=list_id))

    try:
        source_ref_id = int(source_ref_id)
    except (ValueError, TypeError):
        flash("Neplatny zdroj.", "error")
        return redirect(url_for("list_detail", list_id=list_id))

    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM sources WHERE id = %s", (source_ref_id,))
            src = cur.fetchone()

    if not src:
        flash("Zdroj nenalezen.", "error")
        return redirect(url_for("list_detail", list_id=list_id))

    # Determine legacy source_type + source_id for backward compat with generate_lists.py
    sp = src["parametry"] or {}
    stype = src["source_type"]
    parametry = None

    if stype == "agent_native":
        tbl = sp.get("table", "")
        legacy_type = "auth_failures" if tbl == "auth_failures" else "eset_network"
        legacy_sid  = None
    elif stype == "upstream_http":
        legacy_type = "upstream_feed"
        legacy_sid  = sp.get("upstream_feed_id")
    elif stype == "agent_script":
        legacy_type = "agent_events"
        legacy_sid  = None
        parametry   = _json.dumps({
            "module":   sp.get("module", ""),
            "ip_field": sp.get("ip_field", "ipadresa"),
        })
    elif stype == "manual":
        legacy_type = "manual"
        legacy_sid  = None
    else:
        legacy_type = stype
        legacy_sid  = None

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO output_list_sources
                        (list_id, source_type, source_id, parametry, source_ref_id)
                    VALUES (%s, %s, %s, %s, %s)
                """, (list_id, legacy_type,
                      int(legacy_sid) if legacy_sid else None,
                      parametry, source_ref_id))
        flash("Zdroj pridan.", "ok")
    except Exception as e:
        flash(f"Chyba: {e}", "error")

    return redirect(url_for("list_detail", list_id=list_id))


@app.route("/lists/<int:list_id>/sources/<int:source_id>/params", methods=["POST"])
def list_source_params(list_id, source_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT parametry FROM output_list_sources WHERE id = %s AND list_id = %s",
                (source_id, list_id))
            row = cur.fetchone()
            if not row:
                abort(404)
            params = dict(row["parametry"] or {})
            for key in ("vaha", "decay_lambda", "window_days"):
                val = (request.form.get(key) or "").strip()
                if val:
                    try:
                        params[key] = float(val)
                    except ValueError:
                        pass
            cur.execute(
                "UPDATE output_list_sources SET parametry = %s WHERE id = %s",
                (psycopg2.extras.Json(params), source_id))
    flash("Parametry ulozeny.", "ok")
    return redirect(url_for("list_detail", list_id=list_id))


@app.route("/lists/<int:list_id>/sources/<int:source_id>/toggle", methods=["POST"])
def list_source_toggle(list_id, source_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE output_list_sources SET enabled = NOT enabled "
                "WHERE id = %s AND list_id = %s",
                (source_id, list_id))
    return redirect(url_for("list_detail", list_id=list_id))


@app.route("/lists/<int:list_id>/sources/<int:source_id>/delete", methods=["POST"])
def list_source_delete(list_id, source_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM output_list_sources WHERE id = %s AND list_id = %s",
                (source_id, list_id))
    flash("Zdroj odebran.", "ok")
    return redirect(url_for("list_detail", list_id=list_id))


@app.route("/lists/<int:list_id>/sources/auth_failures")
def list_source_auth_failures(list_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM output_lists WHERE id = %s", (list_id,))
            lst = cur.fetchone()
            if not lst:
                abort(404)

            cur.execute("""
                SELECT ipadresa,
                       COUNT(*) AS pocet,
                       MAX(importtime) AS posledni
                FROM auth_failures
                WHERE importtime >= now() - INTERVAL '30 days'
                GROUP BY ipadresa
                ORDER BY pocet DESC
                LIMIT 50
            """)
            top30 = cur.fetchall()

            cur.execute("""
                SELECT ipadresa,
                       COUNT(*) AS pocet,
                       MAX(importtime) AS posledni
                FROM auth_failures
                WHERE importtime >= CURRENT_DATE
                GROUP BY ipadresa
                ORDER BY pocet DESC
                LIMIT 5
            """)
            top_dnes = cur.fetchall()

    return render_template("list_source_detail.html",
                           lst=lst, zdroj="auth_failures",
                           top30=top30, top_dnes=top_dnes)


@app.route("/lists/<int:list_id>/sources/eset_network")
def list_source_eset_network(list_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM output_lists WHERE id = %s", (list_id,))
            lst = cur.fetchone()
            if not lst:
                abort(404)

            cur.execute("""
                SELECT ipadresa,
                       COUNT(*) AS pocet,
                       MAX(importtime) AS posledni
                FROM eset_network_blocks
                WHERE importtime >= now() - INTERVAL '30 days'
                GROUP BY ipadresa
                ORDER BY pocet DESC
                LIMIT 50
            """)
            top30 = cur.fetchall()

            cur.execute("""
                SELECT ipadresa,
                       COUNT(*) AS pocet,
                       MAX(importtime) AS posledni
                FROM eset_network_blocks
                WHERE importtime >= CURRENT_DATE
                GROUP BY ipadresa
                ORDER BY pocet DESC
                LIMIT 5
            """)
            top_dnes = cur.fetchall()

    return render_template("list_source_detail.html",
                           lst=lst, zdroj="eset_network",
                           top30=top30, top_dnes=top_dnes)

# ============================================================
# Clients
# ============================================================

@app.route("/clients")
def clients_list():
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT c.*,
                       (SELECT COUNT(*) FROM agents a
                        WHERE a.client_id = c.id AND a.aktivni = true) AS agent_count,
                       (SELECT COUNT(*) FROM client_ips ci
                        WHERE ci.client_id = c.id) AS ip_count,
                       (SELECT COUNT(*) FROM output_lists ol
                        WHERE ol.client_id = c.id) AS list_count
                FROM clients c
                ORDER BY c.nazev
            """)
            clients = cur.fetchall()
    return render_template("clients.html", clients=clients)


@app.route("/clients/add", methods=["POST"])
def client_add():
    nazev    = request.form.get("nazev", "").strip()
    poznamka = request.form.get("poznamka", "").strip()

    if not nazev or not re.match(r'^[a-zA-Z0-9_\-]+$', nazev):
        flash("Neplatny nazev (jen pismena, cisla, _ a -).", "error")
        return redirect(url_for("clients_list"))

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO clients (nazev, poznamka) VALUES (%s, %s)",
                    (nazev, poznamka or None))
        flash(f"Klient '{nazev}' pridan.", "ok")
    except psycopg2.errors.UniqueViolation:
        flash("Klient s timto nazvem uz existuje.", "error")
    except Exception as e:
        flash(f"Chyba: {e}", "error")

    return redirect(url_for("clients_list"))


@app.route("/clients/<int:client_id>/delete", methods=["POST"])
def client_delete(client_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM clients WHERE id = %s", (client_id,))
    flash("Klient smazan.", "ok")
    return redirect(url_for("clients_list"))


@app.route("/clients/<int:client_id>")
def client_detail(client_id):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM clients WHERE id = %s", (client_id,))
            client = cur.fetchone()
            if not client:
                abort(404)

            cur.execute("""
                SELECT a.*, ag.nazev AS group_name
                FROM agents a
                LEFT JOIN agent_groups ag ON a.group_id = ag.id
                WHERE a.client_id = %s
                ORDER BY a.hostname
            """, (client_id,))
            agents = cur.fetchall()

            cur.execute("""
                SELECT * FROM client_ips WHERE client_id = %s ORDER BY vytvoreno
            """, (client_id,))
            ips = cur.fetchall()

            cur.execute("""
                SELECT id, nazev, list_type, enabled
                FROM output_lists WHERE client_id = %s ORDER BY nazev
            """, (client_id,))
            client_lists = cur.fetchall()

    return render_template("client_detail.html",
                           client=client, agents=agents, ips=ips, client_lists=client_lists)


@app.route("/clients/<int:client_id>/ips/add", methods=["POST"])
def client_ip_add(client_id):
    ip_cidr  = request.form.get("ip_cidr", "").strip()
    popis    = request.form.get("popis", "").strip()

    try:
        ipaddress.ip_network(ip_cidr, strict=False)
    except ValueError:
        flash(f"Neplatna IP/CIDR: {ip_cidr}", "error")
        return redirect(url_for("client_detail", client_id=client_id))

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO client_ips (client_id, ip_cidr, popis) VALUES (%s, %s, %s)",
                    (client_id, ip_cidr, popis or None))
        flash(f"IP {ip_cidr} pridana.", "ok")
    except psycopg2.errors.UniqueViolation:
        flash("Tato IP/CIDR uz je u klienta ulozena.", "error")
    except Exception as e:
        flash(f"Chyba: {e}", "error")

    return redirect(url_for("client_detail", client_id=client_id))


@app.route("/clients/<int:client_id>/ips/<int:ip_id>/delete", methods=["POST"])
def client_ip_delete(client_id, ip_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM client_ips WHERE id = %s AND client_id = %s",
                (ip_id, client_id))
    flash("IP smazana.", "ok")
    return redirect(url_for("client_detail", client_id=client_id))

# ============================================================
# Commands
# ============================================================

@app.route("/commands")
def commands_list():
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT ac.*,
                       a.hostname  AS agent_hostname,
                       ag.nazev   AS group_name,
                       c.nazev    AS client_name
                FROM agent_commands ac
                LEFT JOIN agents       a  ON ac.agent_id  = a.id
                LEFT JOIN agent_groups ag ON ac.group_id  = ag.id
                LEFT JOIN clients      c  ON ac.client_id = c.id
                ORDER BY ac.created_at DESC
                LIMIT 200
            """)
            commands = cur.fetchall()

            cur.execute("SELECT id, hostname FROM agents WHERE aktivni = true ORDER BY hostname")
            agents = cur.fetchall()
            cur.execute("SELECT id, nazev FROM agent_groups ORDER BY nazev")
            groups = cur.fetchall()
            cur.execute("SELECT id, nazev FROM clients ORDER BY nazev")
            clients = cur.fetchall()

    return render_template("commands.html",
                           commands=commands, agents=agents,
                           groups=groups, clients=clients)


@app.route("/commands/add", methods=["POST"])
def command_add():
    command_type = request.form.get("command_type", "powershell")
    if command_type not in ("powershell", "cmd", "panic", "update", "change_group"):
        flash("Neplatny typ prikazu.", "error")
        return redirect(url_for("commands_list"))

    # Build payload based on command type
    if command_type == "update":
        payload = {}
    elif command_type == "change_group":
        try:
            new_group_id = int(request.form.get("new_group_id", ""))
        except (ValueError, TypeError):
            flash("Vyberte cilovou skupinu.", "error")
            return redirect(url_for("commands_list"))
        payload = {"new_group_id": new_group_id}
    elif command_type == "panic":
        script         = request.form.get("script", "").strip()
        retry_interval = request.form.get("retry_interval", "5m").strip()
        timeout        = request.form.get("timeout", "2h").strip()
        if not script:
            flash("Script je povinny.", "error")
            return redirect(url_for("commands_list"))
        payload = {"script": script, "retry_interval": retry_interval or "5m",
                   "timeout": timeout or "2h"}
    else:
        script      = request.form.get("script", "").strip()
        timeout_sec = request.form.get("timeout_sec", "60").strip()
        if not script:
            flash("Script je povinny.", "error")
            return redirect(url_for("commands_list"))
        try:
            t = max(5, min(3600, int(timeout_sec)))
        except ValueError:
            t = 60
        payload = {"script": script, "timeout_sec": t}

    target_type = request.form.get("target_type", "agent")
    agent_id = group_id = client_id = None
    target_all = False

    if target_type == "agent":
        try:
            agent_id = int(request.form.get("target_agent_id", ""))
        except (ValueError, TypeError):
            flash("Vyberte agenta.", "error")
            return redirect(url_for("commands_list"))
    elif target_type == "group":
        try:
            group_id = int(request.form.get("target_group_id", ""))
        except (ValueError, TypeError):
            flash("Vyberte skupinu.", "error")
            return redirect(url_for("commands_list"))
    elif target_type == "client":
        try:
            client_id = int(request.form.get("target_client_id", ""))
        except (ValueError, TypeError):
            flash("Vyberte klienta.", "error")
            return redirect(url_for("commands_list"))
    elif target_type == "all":
        target_all = True
    else:
        flash("Neplatny cil.", "error")
        return redirect(url_for("commands_list"))

    cg_done = False
    sig = None
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    INSERT INTO agent_commands
                        (agent_id, group_id, client_id, target_all,
                         command_type, payload, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'pending')
                    RETURNING id
                """, (agent_id, group_id, client_id, target_all,
                      command_type, psycopg2.extras.Json(payload)))
                cmd_id = cur.fetchone()["id"]

                if command_type == "change_group":
                    ng = payload["new_group_id"]
                    if agent_id:
                        cur.execute("UPDATE agents SET group_id = %s WHERE id = %s",
                                    (ng, agent_id))
                    elif group_id:
                        cur.execute("UPDATE agents SET group_id = %s WHERE group_id = %s",
                                    (ng, group_id))
                    elif client_id:
                        cur.execute("UPDATE agents SET group_id = %s WHERE client_id = %s",
                                    (ng, client_id))
                    elif target_all:
                        cur.execute("UPDATE agents SET group_id = %s WHERE aktivni = true",
                                    (ng,))
                    cg_rows = cur.rowcount
                    cg_done = True
                    cg_result = {"output": f"Group changed for {cg_rows} agent(s).",
                                 "exit_code": 0, "error": None}
                    cur.execute(
                        "UPDATE agent_commands SET status = 'completed', executed_at = now(),"
                        " result = %s WHERE id = %s",
                        (psycopg2.extras.Json(cg_result), cmd_id))
                else:
                    sig = _sign_command(cmd_id, command_type, payload)
                    if sig:
                        cur.execute("UPDATE agent_commands SET signature = %s WHERE id = %s",
                                    (sig, cmd_id))
                    else:
                        app.logger.warning("Command %d created WITHOUT signature (key missing?)", cmd_id)

        if cg_done:
            flash(f"Skupina zmenena. Zaznam #{cmd_id}.", "ok")
        else:
            flash(f"Prikaz #{cmd_id} odeslán{'.' if sig else ' (BEZ podpisu — zkontroluj klic).'}", "ok" if sig else "error")
    except Exception as e:
        flash(f"Chyba: {e}", "error")

    return redirect(url_for("commands_list"))


@app.route("/commands/<int:cmd_id>/cancel", methods=["POST"])
def command_cancel(cmd_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE agent_commands SET status = 'cancelled'
                WHERE id = %s AND status = 'pending'
            """, (cmd_id,))
    flash("Prikaz zrusen.", "ok")
    return redirect(url_for("commands_list"))

# ============================================================
# AI Status
# ============================================================

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
_AI_STATUS_CACHE = {"ts": 0.0, "content": None, "error": None}
_AI_STATUS_TTL = 3600  # 1 hour
_AI_STATUS_GENERATING = False


def _gather_status_context() -> str:
    parts = []
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Agent overview
            cur.execute("""
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE posledni_kontakt >= NOW() - INTERVAL '10 minutes') AS online,
                    COUNT(*) FILTER (WHERE posledni_kontakt < NOW() - INTERVAL '10 minutes'
                                      OR posledni_kontakt IS NULL) AS offline
                FROM agents WHERE aktivni = true
            """)
            s = cur.fetchone()
            parts.append(
                f"## Agent overview\nTotal: {s['total']}, "
                f"Online (last 10min): {s['online']}, Offline: {s['offline']}"
            )

            # Offline agents list
            cur.execute("""
                SELECT a.hostname, a.fqdn, a.posledni_kontakt, a.verze_agenta,
                       ag.nazev AS group_name
                FROM agents a
                LEFT JOIN agent_groups ag ON a.group_id = ag.id
                WHERE a.aktivni = true
                  AND (a.posledni_kontakt < NOW() - INTERVAL '10 minutes'
                       OR a.posledni_kontakt IS NULL)
                ORDER BY a.posledni_kontakt DESC NULLS LAST
                LIMIT 20
            """)
            offline_agents = cur.fetchall()
            if offline_agents:
                lines = [f"- {r['hostname']} ({r['fqdn'] or 'n/a'}) "
                         f"group={r['group_name']} last={r['posledni_kontakt']} "
                         f"ver={r['verze_agenta']}"
                         for r in offline_agents]
                parts.append("### Offline agents:\n" + "\n".join(lines))

            # Failed / errored commands (last 24h)
            cur.execute("""
                SELECT ac.id, COALESCE(a.hostname, 'broadcast') AS hostname,
                       ac.command_type, ac.status, ac.created_at,
                       LEFT(ac.result::text, 300) AS result_preview
                FROM agent_commands ac
                LEFT JOIN agents a ON a.id = ac.agent_id
                WHERE ac.created_at >= NOW() - INTERVAL '24 hours'
                  AND ac.status IN ('failed', 'error', 'signature_failed')
                ORDER BY ac.created_at DESC
                LIMIT 20
            """)
            failed_cmds = cur.fetchall()
            if failed_cmds:
                lines = [f"- #{r['id']} {r['hostname']} [{r['command_type']}] "
                         f"{r['status']} at {r['created_at']}: {r['result_preview']}"
                         for r in failed_cmds]
                parts.append("## Failed commands (last 24h):\n" + "\n".join(lines))

            # Recent commands (last 24h) overview
            cur.execute("""
                SELECT status, COUNT(*) AS n
                FROM agent_commands
                WHERE created_at >= NOW() - INTERVAL '24 hours'
                GROUP BY status ORDER BY n DESC
            """)
            cmd_stats = cur.fetchall()
            if cmd_stats:
                summary = ", ".join(f"{r['status']}={r['n']}" for r in cmd_stats)
                parts.append(f"## Commands last 24h: {summary}")

            # Top auth failures last 24h
            cur.execute("""
                SELECT ipadresa, COUNT(*) AS cnt
                FROM auth_failures
                WHERE importtime >= NOW() - INTERVAL '24 hours'
                GROUP BY ipadresa
                ORDER BY cnt DESC
                LIMIT 15
            """)
            auth_top = cur.fetchall()
            if auth_top:
                lines = [f"- {r['ipadresa']}: {r['cnt']} attempts" for r in auth_top]
                parts.append("## Top auth failure IPs (last 24h):\n" + "\n".join(lines))

            # ESET blocks last 24h
            cur.execute("""
                SELECT COUNT(*) AS n FROM eset_network_blocks
                WHERE importtime >= NOW() - INTERVAL '24 hours'
            """)
            eset_n = cur.fetchone()["n"]
            parts.append(f"## ESET network blocks last 24h: {eset_n}")

            # Upstream feed freshness
            cur.execute("""
                SELECT nazev, enabled, pocet_zaznamu, posledni_refresh
                FROM upstream_feeds
                ORDER BY posledni_refresh DESC NULLS LAST
            """)
            feeds = cur.fetchall()
            if feeds:
                lines = [f"- {r['nazev']} ({'on' if r['enabled'] else 'off'}): "
                         f"{r['pocet_zaznamu']} entries, fetched {r['posledni_refresh']}"
                         for r in feeds]
                parts.append("## Upstream feeds:\n" + "\n".join(lines))

            # Output lists
            cur.execute("""
                SELECT nazev, interval_min, last_generated
                FROM output_lists
                ORDER BY last_generated DESC NULLS LAST
            """)
            out_lists = cur.fetchall()
            if out_lists:
                lines = [f"- {r['nazev']}: last generated {r['last_generated']}, "
                         f"interval {r['interval_min']}min"
                         for r in out_lists]
                parts.append("## Output lists:\n" + "\n".join(lines))

            # Recent agent events (last hour, summary by module)
            cur.execute("""
                SELECT module, COUNT(*) AS n, MAX(created_at) AS latest
                FROM agent_events
                WHERE created_at >= NOW() - INTERVAL '1 hour'
                GROUP BY module
                ORDER BY n DESC
            """)
            ev_summary = cur.fetchall()
            if ev_summary:
                lines = [f"- {r['module']}: {r['n']} events, latest {r['latest']}"
                         for r in ev_summary]
                parts.append("## Agent events last 1h (by module):\n" + "\n".join(lines))

    # Tail error log
    for log_path, label in [
        ("/var/log/xiem/api-error.log", "API error log (last 40 lines)"),
    ]:
        try:
            result = _subprocess.run(
                ["tail", "-n", "40", log_path],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                snippet = result.stdout[-3000:]
                parts.append(f"## {label}:\n```\n{snippet}\n```")
        except Exception:
            pass

    # Journalctl tails
    for unit, label in [
        ("xiem-api", "xiem-api systemd log (last 30 lines)"),
        ("generate-lists", "generate-lists systemd log (last 20 lines)"),
    ]:
        try:
            result = _subprocess.run(
                ["journalctl", "-u", unit, "-n", "30", "--no-pager",
                 "--output=short-iso"],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                snippet = result.stdout[-3000:]
                parts.append(f"## {label}:\n```\n{snippet}\n```")
        except Exception:
            pass

    return "\n\n".join(parts)


def _call_claude(context: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    system_prompt = (
        "You are an infrastructure monitoring assistant for X9.cz, an MSP company "
        "operating ~100 Windows servers for clients. "
        "Analyze the following XIEM (X9 Intrusion & Event Monitor) system data and provide "
        "a concise status report in Czech language using Markdown formatting. "
        "Include: 1) Overall health summary (1-2 sentences), "
        "2) Critical issues or anomalies, "
        "3) Notable events in the last 24 hours, "
        "4) Specific actionable recommendations. "
        "Be concise and practical. Use bullet points and headers. "
        "If everything looks normal, say so clearly."
    )
    msg = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1500,
        messages=[{
            "role": "user",
            "content": (
                f"Current time: {now_str}\n\n"
                f"XIEM system data:\n\n{context}"
            )
        }],
        system=system_prompt,
    )
    return msg.content[0].text


def _ai_status_run():
    """Generate AI status and store in cache. Called from background thread."""
    global _AI_STATUS_GENERATING
    if _AI_STATUS_GENERATING:
        return
    _AI_STATUS_GENERATING = True
    try:
        context = _gather_status_context()
        _AI_STATUS_CACHE["content"] = _call_claude(context)
        _AI_STATUS_CACHE["error"] = None
        _AI_STATUS_CACHE["ts"] = _time.time()
    except Exception as exc:
        _AI_STATUS_CACHE["error"] = str(exc)
    finally:
        _AI_STATUS_GENERATING = False


def _ai_status_loop():
    """Background thread: generate AI status every _AI_STATUS_TTL seconds."""
    _time.sleep(15)  # Let gunicorn workers finish starting up
    while True:
        if ANTHROPIC_API_KEY:
            _ai_status_run()
        _time.sleep(_AI_STATUS_TTL)


_threading.Thread(target=_ai_status_loop, daemon=True, name="ai-status-bg").start()


@app.route("/ai-status")
def ai_status():
    force = request.args.get("refresh") == "1"
    if force and ANTHROPIC_API_KEY and not _AI_STATUS_GENERATING:
        _threading.Thread(target=_ai_status_run, daemon=True).start()
        flash("Refresh zahajen — obnovte stranku za ~30 sekund.", "ok")
        return redirect(url_for("ai_status"))

    cache = _AI_STATUS_CACHE
    age_min = int((_time.time() - cache["ts"]) / 60) if cache["ts"] > 0 else None

    recent_auth = []
    recent_eset = []
    recent_events = []
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT (datum + cas) AS ts, ipadresa, uzivatel, sourceserver
                    FROM auth_failures
                    ORDER BY importtime DESC LIMIT 50
                """)
                recent_auth = cur.fetchall()

                cur.execute("""
                    SELECT cas_udalosti, ipadresa, akce, protokol, sourceserver
                    FROM eset_network_blocks
                    ORDER BY cas_udalosti DESC LIMIT 50
                """)
                recent_eset = cur.fetchall()

                cur.execute("""
                    SELECT ae.created_at, a.hostname, ae.module,
                           LEFT(ae.payload::text, 120) AS payload_preview
                    FROM agent_events ae
                    JOIN agents a ON ae.agent_id = a.id
                    ORDER BY ae.created_at DESC LIMIT 20
                """)
                recent_events = cur.fetchall()
    except Exception:
        pass

    return render_template(
        "ai_status.html",
        content=cache["content"],
        error=cache["error"],
        age_min=age_min,
        generating=_AI_STATUS_GENERATING,
        recent_auth=recent_auth,
        recent_eset=recent_eset,
        recent_events=recent_events,
    )


# ============================================================

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
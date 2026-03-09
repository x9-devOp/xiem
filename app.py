import os
import uuid
import base64
import ipaddress
import json as _json
import re
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
            cur.execute("""
                INSERT INTO agents (token, hostname, fqdn, group_id, ip_adresa, verze_agenta)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (hostname, group_id) DO UPDATE
                    SET token        = EXCLUDED.token,
                        fqdn         = EXCLUDED.fqdn,
                        ip_adresa    = EXCLUDED.ip_adresa,
                        verze_agenta = EXCLUDED.verze_agenta,
                        aktivni      = true
                RETURNING token
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


def _ingest_auth(cur, records, sourceserver):
    inserted = skipped = 0
    for r in records:
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
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE agents SET posledni_kontakt = now() WHERE id = %s",
                        (agent["id"],))
    return jsonify({"ok": True}), 200


@app.route("/api/agent/commands", methods=["GET"])
@require_agent
def agent_get_commands(agent):
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, command_type, payload
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
                     "payload": c["payload"] or {}} for c in commands]), 200


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

    return render_template("agent_detail.html",
                           agent=agent, modules=modules, commands=commands,
                           events=events, clients=clients, now=now)


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
    return render_template("analyze.html")


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
    return redirect(url_for("agents_list"))

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

            cur.execute("SELECT id, nazev FROM upstream_feeds WHERE enabled = true ORDER BY nazev")
            feeds = cur.fetchall()

    return render_template("list_detail.html", lst=lst, sources=sources, feeds=feeds)


@app.route("/lists/<int:list_id>/sources/add", methods=["POST"])
def list_source_add(list_id):
    import json as _json
    source_type = request.form.get("source_type", "")
    source_id   = request.form.get("source_id") or None

    if source_type not in ("auth_failures", "eset_network", "upstream_feed", "manual", "agent_events"):
        flash("Neplatny typ zdroje.", "error")
        return redirect(url_for("list_detail", list_id=list_id))

    if source_type == "upstream_feed" and not source_id:
        flash("Vyberte feed.", "error")
        return redirect(url_for("list_detail", list_id=list_id))

    parametry = None
    if source_type == "agent_events":
        ae_module   = request.form.get("ae_module", "").strip()
        ae_ip_field = request.form.get("ae_ip_field", "ipadresa").strip()
        if not ae_module:
            flash("Zadejte nazev modulu pro agent_events.", "error")
            return redirect(url_for("list_detail", list_id=list_id))
        parametry = _json.dumps({"module": ae_module, "ip_field": ae_ip_field or "ipadresa"})

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO output_list_sources (list_id, source_type, source_id, parametry)
                    VALUES (%s, %s, %s, %s)
                """, (list_id, source_type,
                      int(source_id) if source_id else None,
                      parametry))
        flash("Zdroj pridan.", "ok")
    except Exception as e:
        flash(f"Chyba: {e}", "error")

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
    if command_type not in ("powershell", "cmd", "panic", "update"):
        flash("Neplatny typ prikazu.", "error")
        return redirect(url_for("commands_list"))

    # Build payload based on command type
    if command_type == "update":
        payload = {}
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

                sig = _sign_command(cmd_id, command_type, payload)
                if sig:
                    cur.execute("UPDATE agent_commands SET signature = %s WHERE id = %s",
                                (sig, cmd_id))
                else:
                    app.logger.warning("Command %d created WITHOUT signature (key missing?)", cmd_id)

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

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
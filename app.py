import os
import uuid
import ipaddress
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

    return jsonify({"token": token, "config_url": "/api/agent/config"}), 200


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


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

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
                SELECT a.hostname, a.fqdn, ag.nazev AS group_name, a.ip_adresa,
                       a.posledni_kontakt, a.aktivni
                FROM agents a
                LEFT JOIN agent_groups ag ON a.group_id = ag.id
                WHERE a.aktivni = true
                ORDER BY a.posledni_kontakt DESC NULLS LAST
                LIMIT 10
            """)
            recent_agents = cur.fetchall()

    return render_template("dashboard.html",
        now=now, agents_active=agents_active, agents_online=agents_online,
        feed_ips=feed_ips, feeds_active=feeds_active, manual_ips=manual_ips,
        auth_24h=auth_24h, eset_24h=eset_24h, recent_agents=recent_agents)

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

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
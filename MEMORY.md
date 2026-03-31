# XIEM Project Memory

## Project
XIEM (X9 Intrusion & Event Monitor) — security monitoring for X9.cz MSP.
Flask + PostgreSQL 14 + gunicorn on Ubuntu 22.04.
C# .NET 8 Windows Service agents on client Windows machines.
netaddr version on server: **1.3.0** (important — API differs from 0.x).

## Critical Bug Fixes Applied

### RSA Signature Verification Fix (2026-03-10)
**Bug:** `JavaScriptEncoder.Default` in C# STJ escapes `'` → `\u0027` and HTML chars.
Python `json.dumps` does NOT escape apostrophes.
Result: any PowerShell command with `'` fails verification.
**Fix:** Added `Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping` to `CompactOpts` in `SignatureVerifier.cs`.
**Status:** Fixed. Binary rebuilt and deployed 2026-03-10.

### Commands API missing signature (2026-03-10)
**Bug:** `/api/agent/commands` SELECT and jsonify didn't include `signature` field.
**Fix:** Added `signature` to SELECT and response dict in `app.py`.

### generate_lists.py bugs (2026-03-10)
- `last_generated` never written → fixed
- `interval_min` never respected → fixed

### netaddr 1.x compatibility (2026-03-11)
**Bug:** `netaddr.IPNetwork(x, implicit_prefix=False)` raises TypeError in netaddr 1.x (parameter removed).
All calls silently swallowed → `compute_excludes()` always returned empty IPSet → excludes never applied.
**Fix:** Removed all `implicit_prefix=False` from generate_lists.py. In netaddr 1.x, `IPNetwork("1.2.3.4")` gives /32 host network by default.
RULE: Never use `implicit_prefix` parameter with netaddr on this server.

### auth_failures recent sort (2026-03-18)
**Bug:** Recent 50 records sorted by `importtime` (DB insert time) instead of `(datum+cas)` (event time).
**Fix:** Changed ORDER BY to `(datum+cas) DESC` with `WHERE datum IS NOT NULL AND cas IS NOT NULL`.

## Architecture Notes

### Canonical message format for RSA signing
`"{cmd_id}:{command_type}:{json.dumps(payload, sort_keys=True, separators=(',',':'))}"`
CRITICAL: Must use `UnsafeRelaxedJsonEscaping` in C# STJ.

### Agent group change (2026-03-31)
Route `POST /agents/<id>/assign-group` → UPDATE agents SET group_id.
Dropdown "Skupina" added to agent detail Sprava panel (agent_detail.html).
`agent_assign_client` redirect fixed: returns to agent detail (not agents list).

### Sources unified architecture
`sources` table: unified registry for agent_native, upstream_http, agent_script, manual.
`output_list_sources.source_ref_id` FK → `sources.id`.
`manual_ips.source_id` FK → `sources.id` (ON DELETE CASCADE).
`_resolve_source()` in generate_lists.py maps source_ref_id JOIN to legacy {source_type, source_id, parametry}.

### Analyze routes
- `/analyze` — top 1000 per source type, window 24h/7d/30d, xiemTable
- `/analyze/lookup?ip=` — score breakdown, per-list status, one-click exclude
- `/analyze/exclude` POST — adds IP as typ='exclude' to chosen manual source

### xiemTable JS component
Defined in base.html. Call: `xiemTable(tableId, colDefs, opts)`.
colDefs: `{sort, filter, group, domain}`. `domain:true` extracts domain from FQDN for grouping.
Multi-level grouping: `st.groupCols` ordered array, stored in localStorage.
`defaultGroupCols: [colIdx, ...]` in opts sets initial grouping.

### Gunicorn workers
2 workers. Each loads signing key fresh from disk per request. No shared state.

### AI Status
Background thread (`ai-status-bg`) generates every 3600s using Claude API.
`ANTHROPIC_API_KEY` in `/etc/systemd/system/xiem-api.service` Environment.

### PostgreSQL access
Server LAN IP: 192.168.233.151 (ens160).
listen_addresses = localhost,192.168.233.151
pg_hba.conf allows: 127.0.0.1/32, ::1/128, 192.168.109.0/24, 192.168.233.0/24, 10.9.252.0/24 (all scram-sha-256).
Reload only needed for pg_hba changes: `sudo pg_ctlcluster 14 main reload`.
Full restart needed for listen_addresses changes: `sudo systemctl restart postgresql`.

## Deploy Commands
```bash
# app.py + restart
scp app.py spravce@xiem.x9.cz:/tmp/app.py && ssh spravce@xiem.x9.cz 'sudo cp /tmp/app.py /var/www/flask_xiem/app.py && sudo systemctl restart xiem-api'

# template only (no restart needed)
scp templates/foo.html spravce@xiem.x9.cz:/tmp/foo.html && ssh spravce@xiem.x9.cz 'sudo cp /tmp/foo.html /var/www/flask_xiem/templates/foo.html'

# generate_lists.py
scp generate_lists.py spravce@xiem.x9.cz:/tmp/ && ssh spravce@xiem.x9.cz 'sudo cp /tmp/generate_lists.py /usr/local/bin/generate_lists.py'

# force regenerate a list (reset interval)
ssh spravce@xiem.x9.cz "sudo -u www-data psql \"\$(sudo grep XIEM_DB_DSN /etc/xiem/env | cut -d= -f2-)\" -c \"UPDATE output_lists SET last_generated = NULL WHERE nazev = 'xiem_bad';\"" 2>/dev/null && ssh spravce@xiem.x9.cz 'sudo systemctl start generate-lists.service'
```

## Key File Paths (Server)
- `/var/www/flask_xiem/app.py` — Flask app
- `/var/www/flask_xiem/templates/` — Jinja2 templates
- `/usr/local/bin/generate_lists.py` — blocklist generator
- `/etc/xiem/signing_key.pem` — RSA-2048 private key
- `/etc/xiem/signing_pubkey.pem` — RSA public key
- `/var/www/flask_xiem/agent/xiem-agent.exe` — agent binary for distribution
- `/etc/postgresql/14/main/pg_hba.conf` — DB access control
- `/etc/postgresql/14/main/postgresql.conf` — DB config (listen_addresses)

## Pending / To Monitor
- Per-source scoring params editable via GUI (output_list_sources.parametry JSONB)
- Investigate why auth_failures has no data since 2026-01-14 (pre-v2.0.0 agents)

# currentDate
Today's date is 2026-03-31.

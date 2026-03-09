# XIEM - Claude Code Context

## Co je projekt
XIEM (X9 Intrusion & Event Monitor) - bezpecnostni monitoring pro X9.cz (MSP, ~100 serveru klientu).
Sbira nebezpecne IP z vice zdroju, generuje blocklisty pro pfBlocker na pfSense firewallech.

## Stack
- **Backend:** Flask + PostgreSQL 14 + gunicorn + systemd (Ubuntu 22.04)
- **Agent:** C# .NET 8 Windows Service (na klientskych Windows strojich)
- **Web:** Nginx (reverse proxy + static /IP_LISTS/)
- **DB user:** xiem_writer, DSN v /etc/xiem/env a v systemd unit

## Git workflow
- Repo: https://github.com/x9-devOp/xiem
- Vzdy: git add -> git commit -> git push
- NIKDY git pull pro deploy - zdroj pravdy je server, ne repo
- Po zmenach na serveru: commit + push aby repo bylo aktualni
- Branch: main

## Dulezite cesty
```
/var/www/flask_xiem/app.py          # Flask app (API + management web)
/var/www/flask_xiem/templates/      # Jinja2 templates
/var/www/flask_xiem/venv/           # Python venv
/usr/local/bin/generate_lists.py    # Blocklist generator (systemd timer)
/var/www/html/IP_LISTS/             # Vystupni soubory pro pfBlocker
/etc/xiem/env                       # XIEM_DB_DSN pro generate_lists.py
/etc/systemd/system/xiem-api.service
/etc/systemd/system/generate-lists.service
/etc/systemd/system/generate-lists.timer
/var/log/xiem/api-access.log
/var/log/xiem/api-error.log
```

## DB schema (klic)
```
auth_failures          - Windows Event 4625 (failed logon)
eset_network_blocks    - ESET network protection blocks
agents                 - registrovani Windows agenti
agent_groups           - skupiny (rds / server / workstation)
agent_module_config    - per-group konfigurace modulu
agent_install_secrets  - bootstrap secret pro registraci
upstream_feeds         - externi blocklist feedy (Spamhaus, CINS, ...)
upstream_feed_entries  - zaznamy z feedu (sloupec: zaznam, ne ipadresa)
manual_ips             - rucne zadane zaznamy (sloupec: zaznam, typ: block/exclude)
output_lists           - definice vystupnich souboru
output_list_sources    - zdroje pro kazdy list (parametry v JSONB)
clients                - klienti MSP
whitelist_entries      - per-klient whitelisty
```

## Aktivni bugy
Zadne zname aktivni bugy.

## Pravidla pro tento projekt
- Komentare v kodu: anglicky, bez diakritiky
- Pouze ASCII v zdrojovem kodu
- Git workflow: server -> commit -> push (ne pull-based deploy)
- DB: vzdy pouzivat RealDictCursor, pristup pres named keys (ne indexy)
- Atomicky zapis vystupu: pres .tmp soubor -> rename
- get_db() je @contextmanager - nepouzivat jako obycejnou funkci
- Whitelist/filtrovani: provest pri generovani listu, ne pri sbezu dat

## Scoring model (generate_lists.py)
- Exponencialni decay: `score = weight * e^(-0.05 * age_days)`
- Vahy: ESET=1.5, auth_failures=0.5, manual_block=10.0, upstream_feed=f.vaha
- Threshold: 3.0 pro zarazeni
- /24 agregace: >= 3 IP ze stejneho /24 bloku -> agreguj

## Systemd (bezne prikazy)
```bash
sudo systemctl status xiem-api
sudo systemctl restart xiem-api
sudo journalctl -u xiem-api -n 50 --no-pager
sudo systemctl status generate-lists.timer
sudo journalctl -u generate-lists.service -n 20 --no-pager
```

## DB pripojeni (test)
```bash
sudo -u www-data psql "$(grep XIEM_DB_DSN /etc/xiem/env | cut -d= -f2-)" -c 'SELECT 1;'
```

## Roadmap - co je dal (C5)
- Analyze sekce: /analyze/lookup (proc je IP v blocklistu?) + /analyze/top-offenders
- Per-source scoring parametry editovatelne pres GUI (output_list_sources.parametry JSONB)
- Zprisneni pg_hba.conf (aktualne trust 0.0.0.0/0)
- Agent re-registrace: OPRAVENO (uq_agents_hostname_group constraint + ON CONFLICT fix)

# XIEM - Claude Code Context

## Co je projekt
XIEM (X9 Intrusion & Event Monitor) - bezpecnostni monitoring pro X9.cz (MSP, ~100 serveru klientu).
Sbira nebezpecne IP z vice zdroju, generuje blocklisty pro pfBlocker na pfSense firewallech.
Agent zaroven slouzi jako obecny endpoint-management nastroj (ad-hoc prikazy, panic command).

## Stack
- **Backend:** Flask + PostgreSQL 14 + gunicorn + systemd (Ubuntu 22.04)
- **Agent:** C# .NET 8 Windows Service (na klientskych Windows strojich)
- **Web:** Nginx (reverse proxy + static /IP_LISTS/)
- **DB user:** xiem_writer, DSN v /etc/systemd/system/xiem-api.service (Environment=) a /etc/xiem/env (pro generate_lists.py)

## Git workflow
- Repo: https://github.com/x9-devOp/xiem
- Vzdy: git add -> git commit -> git push
- NIKDY git pull pro deploy - zdroj pravdy je server, ne repo
- Deploy: scp/ssh na spravce@xiem.x9.cz, pak sudo cp + sudo systemctl restart xiem-api
- Branch: main

## Dulezite cesty
```
/var/www/flask_xiem/app.py          # Flask app (API + management web)
/var/www/flask_xiem/templates/      # Jinja2 templates
/var/www/flask_xiem/venv/           # Python venv
/usr/local/bin/generate_lists.py    # Blocklist generator (systemd timer, bezi kazdou minutu)
/var/www/html/IP_LISTS/             # Vystupni soubory pro pfBlocker
/etc/xiem/env                       # XIEM_DB_DSN + XIEM_SIGNING_KEY pro Flask/generate_lists.py
/etc/xiem/signing_key.pem           # RSA-2048 soukromy klic (root:www-data 640)
/etc/xiem/signing_pubkey.pem        # RSA verejny klic (distribuovan agentum pres /api/agent/pubkey)
/etc/systemd/system/xiem-api.service
/etc/systemd/system/generate-lists.service
/etc/systemd/system/generate-lists.timer
/var/log/xiem/api-access.log
/var/log/xiem/api-error.log
/var/www/flask_xiem/agent/xiem-agent.exe  # Distribucni binary pro Windows agenty
```

## Deploy workflow
```bash
# Mac -> server (app.py):
scp app.py spravce@xiem.x9.cz:/tmp/app.py
ssh spravce@xiem.x9.cz 'sudo cp /tmp/app.py /var/www/flask_xiem/app.py && sudo systemctl restart xiem-api'

# Mac -> server (agent binary):
./build_agent.sh   # dotnet publish win-x64 + scp na server

# Server-side one-time setup:
ssh spravce@xiem.x9.cz 'bash -s' < deploy_server.sh
```

## DB schema (klic)
```
auth_failures          - Windows Event 4625 (failed logon) [native modul]
eset_network_blocks    - ESET network protection blocks [native modul]
agent_events           - genericky vystup script modulu (payload JSONB)
agents                 - registrovani Windows agenti (ma client_id FK)
agent_groups           - skupiny (rds / server / workstation) - definuji module config
agent_module_config    - per-group konfigurace modulu (interval_sec, module_type, parametry JSONB)
agent_commands         - ad-hoc prikazy a panic commandy (audit log, vysledky)
agent_install_secrets  - bootstrap secret pro registraci
upstream_feeds         - externi blocklist feedy (Spamhaus, CINS, ...)
upstream_feed_entries  - zaznamy z feedu (sloupec: zaznam, ne ipadresa)
manual_ips             - rucne zadane zaznamy (sloupec: zaznam, typ: block/exclude)
output_lists           - definice vystupnich souboru (interval_min, last_generated)
output_list_sources    - zdroje pro kazdy list (parametry v JSONB)
clients                - klienti MSP (organizacni parametr, nema vliv na config)
client_ips             - povolene zdrojove IP per klient (pro IP restriction agenta)
script_logs            - legacy logovaci tabulka (stare PS/direct-DB agenty, neni aktivne pouzivana)
```
POZOR: whitelist_entries tabulka byla zrusena - whitelisty jsou normalni output_lists.

## Agent architektura (thready)
```
Worker
├── ModuleRunner per modul       (interval ze serveru z agent_module_config)
│   ├── NativeModule             C# implementace (auth_failures, eset_network)
│   └── ScriptModule             PS skript -> JSON stdout -> field_mapping -> ingest
├── CommandPoller                kazych 30s: GET /api/agent/commands
│   ├── pubkey retry             pokud klic neni nacten, zkusi stazeni pred kazdym pollem
│   └── CommandExecutor          PS/CMD + overeni RSA podpisu + POST vysledek
├── PanicWatchdog                monitoruje connectivity k serveru
│   └── po vyprseni timeoutu (z panic commandu) vykona panic akci
└── Heartbeat                    kazych 5 min (posila verzi + FQDN, server updatuje DB)
```

## Agent verze a build
- Verze konstanta: `AgentVersion.Current` v `agent-src/AgentConfig.cs` (aktualne "2.0.0")
- Build: `./build_agent.sh` (dotnet publish win-x64 self-contained + scp na server)
- Install: `.\xiem_install.ps1 -InstallSecret 'SECRET' -Group 'rds'` (jako Administrator)
- Po buildu je binary na serveru v /var/www/flask_xiem/agent/xiem-agent.exe
- Agenti si stahnou novou verzi pres `update` command z GUI Prikazy

## RSA podepisovani prikazu
- Vsechny prikazy jsou podepsany serverem (RSA-PSS-SHA256, salt=32)
- Klic: /etc/xiem/signing_key.pem (root:www-data 640) - Flask potrebuje read prava
- Canonical message: "{id}:{type}:{compact_sorted_json_payload}"
- Agent stahuje pubkey pri startu z /api/agent/pubkey, pinuje na disk
- Pokud pubkey neni k dispozici, CommandPoller ho retryuje pred kazdym pollem
- POZOR: po prvnim spusteni agenta kdyz server nema klic (404) -> restart Windows service

## Module typy (agent_module_config.module_type)
- `native`     - vestaven C# modul, parametry z JSONB
- `powershell` - PS skript z parametry["script"], musi vydat JSON array na stdout
- `cmd`        - pouze pro ad-hoc prikazy, ne pro sber dat do DB

## Script modul - format parametry JSONB
```json
{
  "script": "Get-LocalUser | Select Name,Enabled | ConvertTo-Json",
  "timeout_sec": 30,
  "field_mapping": { "Name": "uzivatel", "Enabled": "aktivni" },
  "ip_field": "ipadresa"
}
```
ip_field: nazev pole v JSON outputu, ktere obsahuje IP adresu (pro generate_lists)

## Agent commands - typy (agent_commands.command_type)
- `powershell` - ad-hoc PS prikaz, vystup ulozeno do result JSONB
- `cmd`        - ad-hoc CMD prikaz
- `update`     - agent se sam aktualizuje (stahne novou verzi z /api/download/agent)
- `panic`      - lokalne cachovan, kryptograficky podepsan, spusti se pri offline > timeout

## Panic command - format payload
```json
{
  "script": "& 'C:\\VeraCrypt\\VeraCrypt.exe' /d /q",
  "retry_interval": "5m",
  "timeout": "2h"
}
```
- retry_interval: jak casto agent zkusi server po spusteni paniku
- timeout: za jak dlouho se panic spusti (od posledniho uspesneho spojeni)
- Panic command je podepsan serverem (RSA), agent overuje public key (stazeny pri registraci)
- Po reconnectu agent ceka na novy panic command ze serveru

## IP restriction agentů
- Pokud ma agent prirazeného klienta a klient ma zaznamy v client_ips -> agent smi volat API
  pouze ze tech IP (CIDR). Bez klienta nebo bez IP zaznamu = zadne omezeni.
- Pri mismatch: 403 + zapis do logu.

## IP filtrovani pri ingestu
- _is_public_ip() v app.py: odmitne privatni (RFC1918), loopback, link-local, multicast,
  neplatne stringy, prazdne hodnoty, "-"
- Aplikuje se na _ingest_auth() a _ingest_eset() pred kazdym INSERT
- auth_failures: historicka privatni IP a "IP not found" stringy byly jednourazove smazany

## Pravidla pro tento projekt
- Komentare v kodu: anglicky, bez diakritiky
- Pouze ASCII v zdrojovem kodu
- Git workflow: server -> commit -> push (ne pull-based deploy)
- DB: vzdy pouzivat RealDictCursor, pristup pres named keys (ne indexy)
- Atomicky zapis vystupu: pres .tmp soubor -> rename
- get_db() je @contextmanager - nepouzivat jako obycejnou funkci
- Zmeny DB se vzdy promitaji do GUI (aby byly sledovatelne a kontrolovatelne)
- Zadne hardcoded hodnoty v agentovi - vse pres parametry pri instalaci nebo ze serveru
- GRANT pro xiem_writer na nových tabulkach: spustit jako postgres superuser

## Scoring model (generate_lists.py)
- Exponencialni decay: `score = weight * e^(-0.05 * age_days)`
- Vahy: ESET=1.5, auth_failures=0.5, manual_block=10.0, upstream_feed=f.vaha
- Threshold: 3.0 pro zarazeni
- /24 agregace: >= 3 IP ze stejneho /24 bloku -> agreguj
- Generovani: kazdu minutu, ale list se generuje jen pokud now()-last_generated > interval_min
- Script moduly: IP se extrahuje podle ip_field z agent_module_config.parametry -> agent_events

## GUI navigace (aktualni stav)
```
Dashboard          (prehled, stav agentu, aktivita)
Infrastruktura:
├── Klienti        (seznam, detail: agenti klienta, IP restriction)
├── Agenti         (seznam, prirazeni ke klientovi, detail)
├── Skupiny        (modul config: typ, interval, skript, params)
└── Prikazy        (novy prikaz: PS/CMD/update/panic, audit log, vysledky)
Blocklists:
├── Upstream Feeds
├── Manual IPs
└── Listy          (definice, zdroje, interval_min, detail/zdroj auth_failures/eset)
Admin:
└── Agent binary   (nahrat novou verzi, postup aktualizace)
Analyza:           (stub - roadmap)
```

## Implementacni fazovy plan - DOKONCENO
- **Faze 1:** DB migrace + agent bez hardcoded hodnot + GUI pro nove sloupce  [DONE]
- **Faze 2:** ScriptModule v agentovi + genericky ingest + generate_lists rozsireni [DONE]
- **Faze 3:** Command poller v agentovi + Flask endpointy + GUI prikazy [DONE]
- **Faze 4:** RSA podepisovani vsech prikazu + PanicWatchdog [DONE]
- **Faze 5:** GUI overhaul (klienti, agenti, skupiny dle nove navigace) [DONE]
- **Faze 6:** Auto-update agenta (update command + binary upload GUI) [DONE]

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
psql "$(sudo grep XIEM_DB_DSN /etc/xiem/env | cut -d= -f2-)" -c 'SELECT 1;'
```

## Roadmap - co je dal
- Analyze sekce: /analyze/lookup (proc je IP v blocklistu?) + /analyze/top-offenders
- Per-source scoring parametry editovatelne pres GUI (output_list_sources.parametry JSONB)
- GUI pro prikazy zatim neni plne nasazeno - pouzit curl na server nebo psql pro odeslani

## Bezpecnost DB (aktualni stav)
- pg_hba.conf: pouze localhost (127.0.0.1/32 scram-sha-256), zadny externi pristup
- listen_addresses = localhost (port 5432 nenasloucha navenek)
- DSN s heslem: /etc/systemd/system/xiem-api.service + /etc/xiem/env (oba mimo git)

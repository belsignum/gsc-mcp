# Betrieb hinter dem NGINX einer Hosting-Verwaltungsoberfläche

Diese Anleitung gilt, wenn auf deinem Server schon ein NGINX läuft, das TLS übernimmt und eine (Sub-)Domain an einen lokalen Port weiterleitet. Viele Hosting-Panels bieten das pro Domain als Option „NGINX als (SSL) Proxy → App-Server auf Port …“ an. Caddy aus der `docker-compose.yml` brauchst du dann nicht. Stattdessen nimmst du `docker-compose.nginx.yml`.

```
Client (Codex, Claude Code)
   │  HTTPS, Authorization: Bearer gsc_…
   ▼
NGINX des Panels (TLS-Zertifikat, Domain)
   │  HTTP auf 127.0.0.1:<Port>
   ▼
ingress        nimmt 127.0.0.1:<Port> an, reicht TCP unverändert weiter
   │
   ▼
gsc-mcp        nur am internen Docker-Netz: kein Internet, kein Zugang zum Host
   │  HTTP CONNECT
   ▼
egress         lässt nur oauth2.googleapis.com und searchconsole.googleapis.com zu
   │  HTTPS
   ▼
Google
```

Warum drei Container: Ein internes Docker-Netz hat keinen Weg ins Internet, veröffentlicht aber auch keine Ports. `ingress` nimmt deshalb die Verbindungen des NGINX an, `egress` ist der einzige Weg nach draußen. Alle drei laufen aus demselben Image.

Im Folgenden steht `gsc.example.com` für deine Domain und `8735` für den Port, den dein Panel anzeigt. Setze überall deine eigenen Werte ein.

## 0. Vorher klären: AGB und Freigabe des Hosters

Lies die AGB deines Hosters, bevor du etwas einrichtest. Viele schränken ein:

- **Dauerhaft laufende Prozesse** („Daemons“) und eigene Software. Ein Container, der ständig läuft, fällt unter diesen Begriff, auch wenn das Panel eine Option für App-Server anbietet.
- **Änderungen an der Webserver-Konfiguration:** oft nur über die Funktionen des Panels erlaubt, alles Weitere nur nach Absprache.
- **Automatisierte Zugriffe und KI:** Manche Hoster verbieten, Panel und Kundenbereich mit Skripten oder KI-Agenten zu bedienen, oder Zugangsdaten, interne URLs und Konfigurationsdaten an externe KI-Dienste weiterzugeben. Bediene Panel und Server dann selbst. Diese Anleitung ist so aufgebaut, dass du jedes Ergebnis selbst auswerten kannst.
- **Backups:** häufig verlangt, dass Sicherungskopien nicht auf dem Server selbst liegen (siehe Schritt 10).

Ist etwas unklar, frag beim Support nach und lass dir die Antwort schriftlich geben. Diese Fragen helfen:

1. Darf auf meinem Server ein kleiner Docker-Aufbau dauerhaft laufen, der über die Panel-Option „Proxy auf App-Server/Port“ erreichbar ist? Es geht um einen MCP-Server, der für KI-Clients die Google Search Console abfragt: drei Container mit zusammen höchstens 2 CPU und 768 MB RAM.
2. Wie stellt ihr Docker bereit: `docker` und `docker compose` per SSH (rootless oder mit Gruppe `docker`), oder nur über das Panel? Darf ich Images aus einem Dockerfile selbst bauen?
3. Startet mein Container nach einem Neustart des Servers wieder von selbst (bei rootless Docker: ist „linger“ für meinen Nutzer aktiv)?
4. Darf ein Container ausgehende HTTPS-Verbindungen zu `oauth2.googleapis.com` und `searchconsole.googleapis.com` aufbauen? Für den Build kommen Docker Hub, `gcr.io` und die npm-Registry dazu.
5. Darf ich eigene Docker-Netze anlegen (`internal: true` mit der Bridge-Option `inhibit_ipv4`)?

## 1. Voraussetzungen auf dem Server prüfen

Per SSH auf dem Server:

```bash
docker version
docker compose version
docker info --format '{{.SecurityOptions}}'
```

- Beide Versionen erscheinen: passt. Enthält die letzte Ausgabe `rootless`, läuft Docker in deinem Nutzerkonto. Das ist für diesen Aufbau in Ordnung; ob die Netztrennung dort genauso greift, zeigt Schritt 7.
- `docker compose` fehlt oder es gibt `permission denied`: Wende dich an den Hoster. Installiere Docker nicht selbst an ihm vorbei.

Lege das Repo **außerhalb** des Web-Verzeichnisses der Domain ab, also nicht unter `htdocs`, `httpdocs` oder `public_html`.

## 2. Google vorbereiten

Je Mandant ein Service Account mit JSON-Schlüssel, in der Search Console nur bei dessen Properties mit „Eingeschränkt“ eingetragen. Schritt für Schritt in der [README](README.md#1-service-account-bei-google-anlegen-je-mandant-einmal). Den Schlüssel lädst du auf deinen eigenen Rechner herunter, nicht auf den Server.

## 3. Panel einstellen

Für die (Sub-)Domain, unter der der Dienst erreichbar sein soll:

1. **Domain anlegen**, falls es sie noch nicht gibt, und den DNS-Eintrag auf den Server zeigen lassen.
2. **Webserver:** die Option „NGINX als (SSL) Proxy → App-Server auf Port …“ wählen. Den angezeigten Port (hier `8735`) notierst du für `.env`. Das Panel erwartet die Anwendung auf `127.0.0.1:<Port>`, genau das macht `docker-compose.nginx.yml`.
3. **SSL-Zertifikat** einschalten, z. B. Let's Encrypt. Wenn es angeboten wird, „HTTPS erzwingen“ und HSTS einschalten. Der Token steht in jedem Request und darf nie unverschlüsselt übertragen werden.
4. **NGINX-Cache für diese Domain ausschalten.** Antworten von `/mcp` enthalten Daten aus der Search Console und dürfen nie zwischengespeichert werden. Der Dienst sendet `Cache-Control: no-store`; verlass dich trotzdem nicht darauf.
5. **Webserver-Logfile:** Das übliche Access-Log von NGINX enthält **nicht** den `Authorization`-Header. Für den normalen Betrieb trotzdem ausschalten (weniger personenbezogene Daten). Erlaubt das Panel ein eigenes Logformat, darf `$http_authorization` darin nie vorkommen.

## 4. Repo holen und `.env` anlegen

```bash
git clone https://github.com/belsignum/gsc-mcp.git ~/gsc-mcp
```

```bash
cd ~/gsc-mcp && cp .env.example .env && chmod 600 .env
```

In `.env` (z. B. mit `nano .env`) eintragen bzw. die Zeilen einkommentieren:

```ini
MCP_DOMAIN=gsc.example.com
COMPOSE_FILE=docker-compose.nginx.yml
MCP_PORT=8735
MCP_TRUST_PROXY=false
```

`COMPOSE_FILE` sorgt dafür, dass jedes `docker compose …` in diesem Ordner die NGINX-Variante nimmt und nie versehentlich Caddy startet. Schlüssel und Tokens gehören **nicht** in die `.env`; die verwaltet `gsc-admin` (Schritt 8).

## 5. Einmalig prüfen, welche Header das Panel-NGINX schickt

Davon hängen der Host-Check und `MCP_TRUST_PROXY` ab. Statt zu raten, schaust du nach. Der Port muss dafür noch frei sein, also vor Schritt 6.

**Terminal 1, per SSH auf dem Server:** ein Wegwerf-Container, der nur Host und `X-Forwarded-For` jeder Anfrage anzeigt:

```bash
docker run --rm --init --name gsc-header-test --read-only --cap-drop ALL --security-opt no-new-privileges --user node -p 127.0.0.1:8735:8080 node:24-alpine node -e "require('http').createServer((q,s)=>{const h=q.headers;console.log(JSON.stringify({host:h.host,'x-forwarded-for':h['x-forwarded-for']??'(fehlt)'}));s.end('ok\n')}).listen(8080)"
```

**Terminal 2, auf deinem eigenen Rechner:** eine Anfrage mit absichtlich gefälschter Absenderadresse:

```bash
curl -s -H 'X-Forwarded-For: 203.0.113.99' https://gsc.example.com/header-test
```

Antwortet `curl` mit `ok`, steht in Terminal 1 eine Zeile wie `{"host":"…","x-forwarded-for":"…"}`. Danach Terminal 1 mit Strg+C beenden.

**`host` auswerten:**

| Ausgabe `host` | Bedeutung | Was tun |
|---|---|---|
| `gsc.example.com` | NGINX reicht die Domain durch | nichts, `MCP_DOMAIN` passt |
| `127.0.0.1:8735` oder `localhost:8735` | NGINX-Standard | nichts, diese Hosts sind immer erlaubt |
| etwas anderes | ungewöhnlich | den Namen ohne Port zusätzlich eintragen: `MCP_DOMAIN=gsc.example.com,anderer-name` |

**`x-forwarded-for` auswerten:**

| Ausgabe `x-forwarded-for` | Bedeutung | `MCP_TRUST_PROXY` |
|---|---|---|
| `(fehlt)` | NGINX setzt den Header nicht | `false` |
| genau `203.0.113.99` | NGINX reicht den Header des Clients ungeprüft durch | **`false`**, `true` wäre hier gefährlich |
| `203.0.113.99, <andere Adresse>` | NGINX hängt die echte Adresse an | `true` |
| nur `<andere Adresse>` | NGINX überschreibt den Header mit der echten Adresse | `true` |

Mit `MCP_TRUST_PROXY=true` nimmt der Dienst den **letzten** Eintrag aus `X-Forwarded-For` als Absender. Reicht NGINX den Header unverändert durch, bestimmt diesen Eintrag der Client, und ein Angreifer könnte für jeden Rateversuch eine neue Adresse erfinden. `ingress` ändert an den Headern nichts; was das NGINX schickt, kommt so beim Dienst an.

**Was `MCP_TRUST_PROXY=false` bedeutet:** Der Dienst sieht für alle Anfragen dieselbe Adresse (die von `ingress`). Das Rate-Limit greift weiterhin, aber für alle gemeinsam: Nach 10 fehlgeschlagenen Anmeldungen in 5 Minuten werden **alle noch unbekannten Tokens** abgewiesen (`429`), bis die 5 Minuten um sind. **Gültige Tokens arbeiten ungestört weiter.** Gegen Raten schützt ohnehin die Länge des Tokens (256 Bit). `false` ist deshalb ein vertretbarer Kompromiss.

## 6. Container starten

```bash
cd ~/gsc-mcp && docker compose up -d --build
```

Der erste Build dauert ein bis zwei Minuten (`npm ci`, TypeScript). Danach:

```bash
docker compose ps
```

```bash
docker compose logs --tail 20
```

Erwartet: drei Dienste mit Status `healthy` (`gsc-mcp`, `egress`, `ingress`) und Zeilen wie

```
gsc-mcp-1  | [gsc-mcp] Freigaben geladen: 0 Tokens, 0 Mandanten (/config/tokens.yaml fehlt noch)
gsc-mcp-1  | [gsc-mcp] 0.1.0 hört auf http://0.0.0.0:3000/mcp (Audit-Log in /data/audit, Google über http://egress:3128)
egress-1   | [egress] hört auf Port 3128, erlaubt: oauth2.googleapis.com:443, searchconsole.googleapis.com:443
ingress-1  | [ingress] Port 3001 → gsc-mcp:3000
```

Warnungen wie `Your kernel does not support … limit` bei rootless Docker heißen: CPU- oder Speicherlimit greifen nicht. Der Dienst läuft trotzdem.

## 7. Netztrennung am Server prüfen

Die Trennung hängt von der Docker-Version und davon ab, ob Docker rootless läuft. Geprüft ist sie an Docker 29; deshalb einmal am Server nachsehen. Die Befehle laufen im eigenen Container (das Image hat keine Shell, daher Node).

**Kein direkter Weg ins Internet:**

```bash
docker compose exec -T gsc-mcp /nodejs/bin/node -e "fetch('https://example.com/',{signal:AbortSignal.timeout(5000)}).then(()=>console.log('FEHLER: Internet direkt erreichbar'),()=>console.log('ok: kein direkter Internetzugang'))"
```

**Kein Zugang zu Diensten des Hosts** (Port 22 von SSH ist auf jedem Server offen und daher ein gutes Ziel):

```bash
docker compose exec -T gsc-mcp /nodejs/bin/node -e "const ip=require('os').networkInterfaces().eth0[0].address.replace(/\.\d+$/,'.1');for(const h of [ip,'172.17.0.1']){const s=require('net').connect(22,h);s.setTimeout(3000,()=>{console.log('ok:',h,'keine Antwort');s.destroy()});s.on('data',d=>{console.log('FEHLER:',h,'antwortet:',String(d).trim());s.destroy()});s.on('error',e=>console.log('ok:',h,e.code))}"
```

**Egress lässt nur Google zu:**

```bash
docker compose exec -T gsc-mcp /nodejs/bin/node -e "for(const t of ['example.com:443','oauth2.googleapis.com:443','searchconsole.googleapis.com:443']){const s=require('net').connect(3128,'egress',()=>s.write('CONNECT '+t+' HTTP/1.1\r\nHost: '+t+'\r\n\r\n'));s.once('data',d=>{console.log(t,'→',String(d).split('\r\n')[0]);s.destroy()})}"
```

Erwartet: `ok` in den ersten beiden Prüfungen; `example.com:443 → HTTP/1.1 403 Forbidden` und `200 Connection Established` für die beiden Google-Ziele. Steht irgendwo `FEHLER`, den Dienst nicht freigeben und das Ergebnis prüfen (oft: rootless Docker oder eine alte Docker-Version).

## 8. Mandanten und Tokens anlegen

Auf deinem eigenen Rechner, mit dem heruntergeladenen Schlüssel (`benutzer@server` durch deinen SSH-Zugang ersetzen). Der Schlüssel geht direkt in den Container, ohne Kopie auf dem Server:

```bash
ssh benutzer@server 'cd ~/gsc-mcp && docker compose run --rm -T gsc-admin tenant add kunde-a' < gsc-kunde-a.json
```

```bash
ssh benutzer@server 'cd ~/gsc-mcp && docker compose run --rm -T gsc-admin token add --user anna --tenant kunde-a --property sc-domain:example.com'
```

Der Token erscheint genau einmal. Alle Befehle stehen in der [README](README.md#mandanten-und-tokens-verwalten).

## 9. Von außen prüfen

Auf deinem eigenen Rechner:

```bash
curl -s https://gsc.example.com/health
```

Erwartet: `{"status":"ok"}`.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://gsc.example.com/mcp
```

Erwartet: `401` (ohne Token kein Zugang).

```bash
curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://gsc.example.com:8735/health
```

Erwartet: `000` (keine Verbindung). Der Port ist von außen nicht erreichbar.

Mit Token: Lies ihn verdeckt ein, damit er nicht in der Shell-History landet:

```bash
printf 'gsc-Token: ' && read -rs GSC_MCP_TOKEN && echo && curl -s -H "Authorization: Bearer $GSC_MCP_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gsc_list_properties","arguments":{}}}' https://gsc.example.com/mcp; unset GSC_MCP_TOKEN
```

Erwartet: eine Zeile `data: {"result":{"content":[{"type":"text","text":"{\n \"count\": …` mit den freigegebenen Properties. Steht dort „Die Anmeldung bei Google ist … fehlgeschlagen“, passt der Schlüssel nicht; ist die Liste leer, ist der Service Account in der Search Console noch nicht eingetragen.

## 10. Betrieb

**Updates einspielen:**

```bash
cd ~/gsc-mcp && git pull && docker compose up -d --build
```

Die Basis-Images sind per Digest festgelegt. Neue Digests (Sicherheitsupdates von Debian, Alpine und Node) kommen als Dependabot-PR ins Repo; nach dem Merge holt `git pull` sie, und der Build nutzt sie.

**Logs ansehen** (Start- und Fehlermeldungen, nie ein Token; Docker behält höchstens 3 × 1 MB je Container):

```bash
cd ~/gsc-mcp && docker compose logs --tail 50
```

**Audit-Log ansehen:**

```bash
cd ~/gsc-mcp && docker compose exec -T gsc-mcp /nodejs/bin/node -e "const fs=require('fs');for(const f of fs.readdirSync('/data/audit').sort())process.stdout.write(fs.readFileSync('/data/audit/'+f))" | jq -c '{time, user, tool: (.tool // .action), property, result, reason}'
```

**Nach einem Neustart des Servers** startet Docker die Container wieder (`restart: unless-stopped`). Bei rootless Docker gilt das nur, wenn der Docker-Dienst deines Nutzers ohne Anmeldung startet (Frage 3 aus Schritt 0).

**Rate-Limit und Kontingente** liegen im Arbeitsspeicher. Nach einem Neustart des Containers sind sie leer.

## 11. Backup

Drei Volumes, unterschiedlich zu behandeln:

| Volume | Inhalt | Sichern |
|---|---|---|
| `gsc-mcp_audit_data` | Audit-Log | ja |
| `gsc-mcp_gsc_config` | Freigaben: Mandanten, Token-Hashes, Whitelists | ja |
| `gsc-mcp_gsc_keys` | private Schlüssel der Service Accounts | **nein**: Schlüssel liegen im Passwortmanager und lassen sich mit `tenant key` neu einspielen. Eine Kopie im Backup wäre eine weitere Stelle, an der sie abfließen können |

Sichere **direkt auf deinen eigenen Rechner**, ohne Zwischenkopie auf dem Server:

```bash
ssh benutzer@server 'cd ~/gsc-mcp && docker compose cp gsc-mcp:/data/audit -' > gsc-audit-$(date +%F).tar
```

```bash
ssh benutzer@server 'cd ~/gsc-mcp && docker compose cp gsc-mcp:/config -' > gsc-config-$(date +%F).tar
```

**Zurückspielen** nicht mit `docker compose cp`: Das setzt den Besitzer auf root, danach kann der Dienst die Dateien nicht mehr lesen. Stattdessen mit einem Wegwerf-Container als Nutzer 65532 (der Dienst ist dabei kurz gestoppt):

```bash
ssh benutzer@server 'cd ~/gsc-mcp && docker compose stop gsc-mcp && docker run --rm -i --network none --user 65532:65532 -v gsc-mcp_gsc_config:/config busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec tar -C / -xf - && docker compose start gsc-mcp' < gsc-config-JJJJ-MM-TT.tar
```

Für das Audit-Log entsprechend mit `-v gsc-mcp_audit_data:/data` und `tar -C /data -xf -`.

## 12. Fehlersuche

| Symptom | Ursache und Abhilfe |
|---|---|
| `502 Bad Gateway` | Die Container laufen nicht oder hören auf einem anderen Port. Auf dem Server: `docker compose ps`, dann `curl -s http://127.0.0.1:8735/health`. `MCP_PORT` muss dem Port im Panel entsprechen. |
| `403` mit `Invalid Host` | Das NGINX schickt einen Host, der nicht erlaubt ist. Schritt 5 (Tabelle `host`). |
| `401` | Kein oder unbekannter Token. Mit `gsc-admin token list` nachsehen; widerrufene Tokens stehen dort nicht mehr. |
| `429` | Zu viele Fehlversuche (Schritt 5), bis zu 5 Minuten warten; oder mehr als 8 gleichzeitige Requests mit einem Token. |
| „Limit erreicht: höchstens … Aufrufe“ | Aufruflimit je Token (`GSC_MAX_CALLS_PER_MINUTE`, `GSC_MAX_CALLS_PER_DAY`). Für geplante große Auswertungen vorübergehend erhöhen. |
| `503` mit „nicht richtig konfiguriert“ | Die Freigabedatei ist fehlerhaft (Meldung in `docker compose logs gsc-mcp`). `gsc-admin check` zeigt die Stelle. |
| „Property nicht verfügbar“ | Property nicht in der Whitelist des Tokens, falsch geschrieben, oder der Service Account ist in der Search Console nicht eingetragen. Das Audit-Log zeigt den Grund (`whitelist` oder `google_403`). |
| „Anmeldung bei Google … fehlgeschlagen“ | Schlüssel ungültig oder in der Google Cloud Console gelöscht. Neuen Schlüssel mit `tenant key` einspielen. |
| „Google ist gerade nicht erreichbar“ | Egress-Proxy oder Google nicht erreichbar: `docker compose logs egress` und Schritt 7. |
| „Sperre von einem früheren Aufruf“ bei `gsc-admin` | Ein Aufruf wurde abgebrochen. Läuft sicher kein anderer: `docker compose run --rm -T gsc-admin unlock`. |
| `Keine Schreibrechte` bei `gsc-admin` | `gsc-admin` mit `docker compose run --rm -T gsc-admin …` aufrufen, nicht per `exec` im Server-Container (der sieht Freigaben nur lesend). |
| `port is already allocated` | Ein anderer Prozess nutzt den Port, z. B. ein vergessener Header-Test: `docker stop gsc-header-test`. |

## Was getestet ist

Lokal mit Docker 29.3 getestet (`scripts/compose-check.sh`, läuft auch in jedem PR-Check): `docker-compose.nginx.yml` mit einem Wegwerf-Schlüssel.

- Drei Container `healthy`, alle als Nutzer 65532 mit schreibgeschütztem Dateisystem, ohne Capabilities, mit `no-new-privileges` und Node Permission Model. Image ohne Shell; der Code gehört root.
- Port nur auf `127.0.0.1`; `/health` antwortet, `/mcp` ohne Token mit `401`, andere Pfade mit `404`. Mit Token: `gsc_whoami`, fremde Property mit „Property nicht verfügbar“.
- `gsc-admin` legt Mandant und Token an; der Server-Container kann die Freigaben nicht ändern (`EROFS`).
- Server-Container: kein direkter Weg ins Internet, kein Zugang zu einem Testdienst auf dem Host; Egress lehnt `example.com` und `169.254.169.254` ab und lässt die beiden Google-Ziele zu. Gegenprobe ohne `inhibit_ipv4`: der Testdienst auf dem Host ist erreichbar, die Prüfung schlägt an.
- Eine Anfrage mit dem Wegwerf-Schlüssel ging über den Egress-Proxy bis zu Google und kam mit `invalid_grant: account not found` zurück; das Audit-Log enthält Googles Meldung, keinen Token und keinen Schlüssel.
- Rate-Limit mit `MCP_TRUST_PROXY=false` und gefälschtem `X-Forwarded-For`: 10 × `401`, danach `429`; der gültige Token arbeitet weiter. Requests über 1 MB: `413`. Widerruf per `gsc-admin` wirkt sofort.
- Sicherung per `docker compose cp` und Wiederherstellung mit busybox als Nutzer 65532: Besitzer und Rechte (`0700`/`0600`) bleiben erhalten.

Erst auf deinem Server prüfbar: was das Panel-NGINX schickt (Schritt 5), die Netztrennung unter der dortigen Docker-Version (Schritt 7), das Zertifikat und ein echter Abruf mit einem Schlüssel, der in der Search Console eingetragen ist.

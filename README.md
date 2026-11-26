# gsc-mcp

MCP-Server für die [Google Search Console](https://search.google.com/search-console). Er gibt KI-Clients wie Codex, Claude Code oder Cursor lesenden Zugriff auf:

- **Leistungsdaten der Suche:** Klicks, Impressionen, CTR und Position nach Suchanfrage, Seite, Land, Gerät, Datum und Darstellung
- **Sitemaps:** eingereichte Sitemaps mit Status, Fehlern und Warnungen
- **URL-Prüfung:** Index-Status einer URL, wie in der Search Console

Der Dienst läuft zentral in einem Docker-Container. Nutzer bekommen einen **persönlichen Token dieses Dienstes**, nie einen Google-Schlüssel. Die Google-Schlüssel bleiben auf dem Server.

## Mandantentrennung

Die Trennung zwischen Kunden (Mandanten) greift auf zwei Ebenen. Jede für sich verhindert, dass ein Token Daten eines anderen Mandanten sieht.

**Ebene 1, im Dienst:** Jeder Token gehört zu genau einem Mandanten und hat eine **Whitelist von Properties**. Jedes Tool bekommt die Property als Pflichtangabe; der Dienst vergleicht sie **exakt** mit der Whitelist. `sc-domain:example.com` gibt also nicht `sc-domain:shop.example.com` frei, `https://www.example.com/` nicht `https://www.example.com/shop/`. Ist eine Property nicht freigegeben, geht **keine Anfrage an Google**, und die Antwort lautet immer gleich: „Property nicht verfügbar“. Dieselbe Antwort kommt für Properties, die es nicht gibt, und für solche, auf die Google den Zugriff verweigert. Ein Token kann so nicht herausfinden, welche Properties andere Mandanten haben.

**Ebene 2, bei Google:** Jeder Mandant hat einen **eigenen Service Account**, der in der Search Console nur bei den Properties dieses Mandanten eingetragen ist (Berechtigung „Eingeschränkt“). Ein Aufruf nutzt immer den Service Account des Mandanten, zu dem der Token gehört. Selbst ein Fehler in der Whitelist öffnet deshalb keinen fremden Mandanten. Angefordert wird nur der Scope `webmasters.readonly`.

Beides ist durch Pflicht-Tests im PR-Check abgesichert ([test/isolation.test.ts](test/isolation.test.ts)).

## Tools

| Tool | Zweck | Fragt Google |
|---|---|---|
| `gsc_whoami` | Nutzer, Mandant und freigegebene Properties dieses Tokens | nein |
| `gsc_list_properties` | Freigegebene Properties, auf die der Service Account Zugriff hat, mit Berechtigungsstufe | ja |
| `gsc_search_analytics` | Leistungsdaten für einen Zeitraum, mit Dimensionen, Filtern und Suchtyp (`web`, `image`, `video`, `news`, `discover`, `googleNews`); höchstens 5000 Zeilen je Abfrage | ja |
| `gsc_list_sitemaps` | Eingereichte Sitemaps einer Property | ja |
| `gsc_get_sitemap` | Details einer Sitemap | ja |
| `gsc_inspect_url` | Index-Status einer URL; die URL muss zur Property gehören | ja |

Es gibt bewusst **keine schreibenden Tools**: Sitemaps einreichen oder löschen, Properties anlegen oder entfernen geht nur in der Search Console selbst. Auch Freigaben lassen sich nicht über MCP ändern, nur über `gsc-admin` auf dem Server. So kann ein manipulierter Text in den Suchdaten (Prompt Injection) keine Freigabe ändern.

**Limits:**

- **Aufrufe je Token:** höchstens 60 pro Minute und 2000 pro Tag (`GSC_MAX_CALLS_PER_MINUTE`, `GSC_MAX_CALLS_PER_DAY`), dazu höchstens 8 gleichzeitige Requests. Es zählt jeder Aufruf, auch abgelehnte. Alle Mandanten teilen sich das Kontingent des Google-Cloud-Projekts und das Audit-Log; ein Agent in einer Schleife soll keines von beiden für alle aufbrauchen.
- **URL-Prüfungen je Mandant:** höchstens 500 pro Tag (`GSC_MAX_INSPECTIONS_PER_DAY`). Google erlaubt je Property 2000 pro Tag.

## Audit-Log

Jeder Tool-Aufruf und jede Änderung über `gsc-admin` steht im Audit-Log: eine Datei pro Monat im JSON-Lines-Format unter `/data/audit` (Volume `audit_data`), Rechte `0600`.

```json
{"v":1,"time":"2026-11-26T09:05:03.120Z","kind":"call","user":"anna","tenant":"kunde-a","tokenId":"t_1f7b27fec062","tool":"gsc_search_analytics","property":"sc-domain:example.com","params":{"startDate":"2026-10-01","endDate":"2026-10-31","dimensions":["query"],"rowLimit":1000},"result":"ok","rows":1000,"ms":412}
{"v":1,"time":"2026-11-26T09:05:09.877Z","kind":"call","user":"anna","tenant":"kunde-a","tokenId":"t_1f7b27fec062","tool":"gsc_list_sitemaps","property":"sc-domain:example.org","params":{},"result":"denied","reason":"whitelist","ms":0}
{"v":1,"time":"2026-11-26T09:10:44.002Z","kind":"admin","actor":"gsc-admin","action":"token.revoke","tokenId":"t_1f7b27fec062","user":"anna","tenant":"kunde-a"}
```

- **Inhalt:** wer, welches Tool, welche Property, welche Parameter, Ergebnis (`ok`, `denied`, `error`), interner Grund (`whitelist`, `google_403`, `limit` …), Zeilenzahl und Dauer. **Nie** der Token, sein Hash, ein Schlüssel oder die Daten, die Google geliefert hat.
- **Ohne Protokoll keine Daten:** Lässt sich ein Aufruf nicht protokollieren, gibt der Dienst das Ergebnis nicht heraus.
- **Größe:** höchstens 2 kB je Zeile (lange Parameter werden weggelassen), rund 400 Byte im Normalfall. Von Ablehnungen wegen eines Limits kommt nur die erste ins Log.
- **Aufbewahrung:** 365 Tage (`GSC_AUDIT_RETENTION_DAYS`), höchstens 500 MB (`GSC_AUDIT_MAX_MB`), das reicht für etwa 1000 Aufrufe am Tag über drei Jahre. Ab 80 % steht eine Warnung im Server-Log. Ist das Log voll, liefert der Dienst keine Daten mehr, bis alte Monatsdateien ablaufen oder der Wert erhöht wird.

## Betrieb

Zwei Varianten, beide mit derselben Härtung:

- **VPS mit Caddy** (`docker-compose.yml`): Caddy holt das TLS-Zertifikat von Let's Encrypt.
- **Hinter einem vorhandenen NGINX** (`docker-compose.nginx.yml`), etwa dem einer Hosting-Verwaltungsoberfläche mit „Proxy auf App-Server/Port“. Schritt für Schritt in [DEPLOY.md](DEPLOY.md).

```
Client (Codex, Claude Code)
   │  HTTPS, Authorization: Bearer gsc_…
   ▼
Caddy bzw. NGINX des Panels (TLS)
   │
   ▼
gsc-mcp          nur am internen Docker-Netz: kein Internet, kein Zugang zum Host
   │  HTTP CONNECT
   ▼
egress           Allowlist: oauth2.googleapis.com, searchconsole.googleapis.com
   │  TLS Ende zu Ende
   ▼
Google
```

Dazu kommt `gsc-admin`, ein Einmal-Container ohne Netzwerk für die Verwaltung.

### Mit Caddy auf einem VPS

**Voraussetzungen:** ein VPS mit Docker, eine Subdomain wie `gsc.example.com`, deren DNS-Eintrag auf den VPS zeigt, und offene Ports 80 und 443.

```bash
git clone https://github.com/belsignum/gsc-mcp.git && cd gsc-mcp
```

```bash
cp .env.example .env && chmod 600 .env   # MCP_DOMAIN eintragen
```

```bash
docker compose up -d --build
```

```bash
curl https://gsc.example.com/health
```

Erwartete Antwort: `{"status":"ok"}`. Danach Mandanten und Tokens anlegen (nächster Abschnitt).

### Konfiguration

| Variable | Pflicht | Bedeutung |
|---|---|---|
| `MCP_DOMAIN` | ja | Öffentlicher Hostname; für TLS und den Host-Check |
| `MCP_PORT` | ja (NGINX-Variante) | Port auf `127.0.0.1`, an den das vorhandene NGINX weiterleitet |
| `MCP_TRUST_PROXY` | nein | `true` = Client-IP aus `X-Forwarded-For` (die Caddy-Variante setzt es, die NGINX-Variante nur nach Prüfung, siehe [DEPLOY.md](DEPLOY.md)) |
| `GSC_MAX_CALLS_PER_MINUTE` | nein | Aufrufe je Token und Minute (Standard 60, `0` = unbegrenzt) |
| `GSC_MAX_CALLS_PER_DAY` | nein | Aufrufe je Token und Tag (Standard 2000, `0` = unbegrenzt) |
| `GSC_MAX_INSPECTIONS_PER_DAY` | nein | URL-Prüfungen je Mandant und Tag (Standard 500, `0` = unbegrenzt) |
| `GSC_AUDIT_RETENTION_DAYS` | nein | Aufbewahrung des Audit-Logs in Tagen (Standard 365, `0` = unbegrenzt) |
| `GSC_AUDIT_MAX_MB` | nein | Maximale Größe des Audit-Logs (Standard 500, `0` = unbegrenzt) |

Die Compose-Dateien setzen außerdem `GSC_EGRESS_PROXY`, `GSC_CONFIG`, `GSC_KEY_DIR` und `GSC_AUDIT_DIR`; die bleiben unverändert.

## Mandanten und Tokens verwalten

Verwaltet wird nur auf dem Server, mit `gsc-admin`. Das ist ein eigener Einmal-Container ohne Netzwerk; nur er darf Freigaben und Schlüssel schreiben. Der Server sieht beides nur lesend und liest Änderungen nach spätestens einer Sekunde ein, ohne Neustart.

```bash
docker compose run --rm -T gsc-admin --help
```

### 1. Service Account bei Google anlegen (je Mandant einmal)

1. In der [Google Cloud Console](https://console.cloud.google.com/) ein Projekt wählen oder anlegen und die **Google Search Console API** aktivieren.
2. Unter **IAM & Verwaltung → Dienstkonten** ein Dienstkonto je Mandant anlegen, z. B. `gsc-kunde-a`. **Keine** Rollen vergeben, keine domainweite Delegation.
3. Beim Dienstkonto unter **Schlüssel → Schlüssel hinzufügen → JSON** einen Schlüssel erzeugen. Die Datei wird einmal heruntergeladen.
4. In der **Search Console** bei jeder Property des Mandanten unter **Einstellungen → Nutzer und Berechtigungen** die E-Mail-Adresse des Dienstkontos mit der Berechtigung **„Eingeschränkt“** hinzufügen. Nur bei diesem Mandanten.

### 2. Mandant mit Schlüssel anlegen

Den Schlüssel direkt vom eigenen Rechner per SSH übergeben, ohne Kopie auf dem Server (`benutzer@server` und den Pfad anpassen):

```bash
ssh benutzer@server 'cd ~/gsc-mcp && docker compose run --rm -T gsc-admin tenant add kunde-a' < gsc-kunde-a.json
```

`gsc-admin` prüft den Schlüssel, speichert nur die nötigen Felder mit Rechten `0600` im Volume `gsc_keys` und trägt den Service Account beim Mandanten ein. Ein Service Account kann nur zu einem Mandanten gehören. Danach die heruntergeladene Datei vom eigenen Rechner löschen oder in den Passwortmanager legen.

Schlüssel wechseln (gleicher Service Account): `tenant key kunde-a` mit dem neuen Schlüssel auf stdin, danach den alten Schlüssel in der Google Cloud Console löschen.

### 3. Token anlegen

Properties genau in der Schreibweise der Search Console angeben: Domain-Properties als `sc-domain:example.com`, URL-Präfix-Properties als vollständige URL mit `/` am Ende.

```bash
ssh benutzer@server 'cd ~/gsc-mcp && docker compose run --rm -T gsc-admin token add --user anna --tenant kunde-a --property sc-domain:example.com --property https://www.example.com/'
```

Der Token erscheint **genau einmal**; gespeichert wird nur sein SHA-256-Hash. Ihn sicher an den Nutzer übergeben, etwa über einen Passwortmanager.

| Befehl | Zweck |
|---|---|
| `token list [--tenant kunde-a]` | Tokens mit ID, Nutzer, Mandant und Properties (ohne Token und Hash) |
| `token properties <id> --property …` | Whitelist eines Tokens ersetzen |
| `token revoke <id>` | Token widerrufen; wirkt nach spätestens einer Sekunde |
| `tenant list` | Mandanten mit Service Account und Zahl der Tokens |
| `tenant remove kunde-a` | Mandant und Schlüssel löschen (nur ohne Tokens) |
| `check` | Freigabedatei und Schlüssel prüfen |
| `unlock` | Sperre eines abgebrochenen `gsc-admin`-Aufrufs entfernen (wird nie automatisch entfernt) |

## Clients verbinden

Jeder Nutzer braucht die URL `https://gsc.example.com/mcp` und seinen Token. Den Token in einer Umgebungsvariable halten, z. B. `GSC_MCP_TOKEN`, nicht im Klartext in einer Konfigurationsdatei.

### Codex

`~/.codex/config.toml`:

```toml
[mcp_servers.gsc]
url = "https://gsc.example.com/mcp"
bearer_token_env_var = "GSC_MCP_TOKEN"
```

### Claude Code

```bash
claude mcp add --transport http --scope user gsc https://gsc.example.com/mcp --header "Authorization: Bearer $GSC_MCP_TOKEN"
```

Dabei landet der Token im Klartext in der Konfiguration von Claude Code. Ohne das geht es mit einer `.mcp.json`, die ihn aus der Umgebung liest:

```json
{
  "mcpServers": {
    "gsc": {
      "type": "http",
      "url": "https://gsc.example.com/mcp",
      "headers": { "Authorization": "Bearer ${GSC_MCP_TOKEN}" }
    }
  }
}
```

### Cursor / VS Code

`.cursor/mcp.json` bzw. `.vscode/mcp.json` (dort heißt der Schlüssel `servers` statt `mcpServers`):

```json
{
  "mcpServers": {
    "gsc": {
      "url": "https://gsc.example.com/mcp",
      "headers": { "Authorization": "Bearer <GSC_MCP_TOKEN>" }
    }
  }
}
```

### claude.ai im Browser / ChatGPT

Diese Clients erwarten OAuth und können keinen festen Bearer-Header senden. Dafür bräuchte der Dienst eine zusätzliche OAuth-Schicht. Die ist nicht enthalten.

## Lokal mit eigenem Schlüssel (stdio)

Zum Ausprobieren auf dem eigenen Rechner, ohne Server und ohne Tokens. Der Client startet den Dienst selbst:

```bash
npm install && npm run build
```

```json
{
  "mcpServers": {
    "gsc": {
      "command": "node",
      "args": ["/absoluter/pfad/zu/gsc-mcp/dist/stdio.js"],
      "env": { "GSC_KEY_FILE": "/pfad/zum/schluessel.json", "GSC_PROPERTIES": "sc-domain:example.com" }
    }
  }
}
```

`GSC_PROPERTIES` ist auch hier Pflicht: Auch lokal fragt der Dienst nur freigegebene Properties ab.

## Sicherheit

- **Eigene Tokens, nur als Hash gespeichert.** 32 Zufallsbytes, Format `gsc_…`. Ohne gültigen Token antwortet `/mcp` mit `401`, auch die Tool-Liste bleibt verborgen.
- **Schutz gegen Token-Raten:** Nach 10 Fehlversuchen in 5 Minuten wird die IP-Adresse (IPv6: das /64-Netz) für unbekannte Tokens gesperrt (`429`). Gültige Tokens arbeiten weiter.
- **Container gehärtet:** Laufzeit-Image ohne Shell und Paketmanager (distroless), Nutzer `nonroot`, schreibgeschütztes Dateisystem, keine Capabilities, Node Permission Model, Ressourcenlimits.
- **Ausgehend nur zu Google:** Der Server hängt an einem internen Docker-Netz ohne Internet und ohne Zugang zu Diensten des Hosts. Ins Internet kommt er nur über den Egress-Proxy, und der lässt nur `oauth2.googleapis.com` und `searchconsole.googleapis.com` zu.
- **Host-Check gegen DNS-Rebinding,** Requests bis 1 MB, eine JSON-RPC-Nachricht je Request, keine offenen Streams, kein Access-Log mit Tokens.
- **Texte aus der Search Console sind Daten, keine Anweisungen.** Suchanfragen stammen von beliebigen Menschen im Internet und können präparierte Anweisungen enthalten.

Das vollständige Sicherheitsreview mit Befunden, Nachweisen und verbleibenden Risiken steht in [SECURITY.md](SECURITY.md).

## Entwicklung

```bash
npm install
npm test          # Tests gegen einen nachgebauten Google-Server, inkl. Pflicht-Tests zur Mandantentrennung
npm run typecheck
scripts/compose-check.sh   # Compose-Aufbau mit Wegwerf-Schlüssel prüfen (Docker nötig)
```

Node.js ≥ 24. Der Quellcode in `src/` läuft dank Type-Stripping direkt mit Node; `npm run build` erzeugt `dist/` für Docker.

### Rauchtest am echten Konto

```bash
node scripts/smoke-google.ts /pfad/zum/schluessel.json sc-domain:example.com https://www.example.com/
```

Meldet sich mit dem Schlüssel bei Google an und prüft Properties, Leistungsdaten, Sitemaps und, mit URL, die URL-Prüfung. Ausgegeben werden nur Zusammenfassungen, keine Suchanfragen. Ändert nichts bei Google.

Jeder PR durchläuft den Check in `.github/workflows/check.yml`: Tests, Typprüfung, Aufbau und Prüfung des Compose-Aufbaus, `npm audit`. Dependabot schlägt Updates für npm, Basis-Images, Compose und Actions als PR vor.

## Lizenz

[MIT](LICENSE)

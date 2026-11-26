#!/usr/bin/env bash
# Prüft den laufenden Compose-Aufbau (NGINX-Variante) mit einem Wegwerf-Schlüssel:
# Härtung der Container, Egress nur zu Google, Zugang nur mit Token und Whitelist.
# Läuft lokal und im PR-Check. Braucht Docker mit Compose, curl und Node (für den Testschlüssel).
#
#   scripts/compose-check.sh
#
# Startet ein eigenes Compose-Projekt (gsc-check) und räumt es danach samt Volumes wieder ab.
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT=gsc-check
PORT=${CHECK_PORT:-18799}
WORK=$(mktemp -d)
export MCP_DOMAIN=mcp.example.com MCP_PORT=$PORT MCP_TRUST_PROXY=false
dc() { docker compose -f docker-compose.nginx.yml -p "$PROJECT" "$@"; }
fails=0
ok() { printf 'ok     %s\n' "$1"; }
bad() { printf 'FEHLER %s\n' "$1"; fails=$((fails + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (erwartet: $3, erhalten: $2)"; fi; }
cleanup() { dc down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

# Wegwerf-Schlüssel: gültiges Format, bei Google unbekannt
node -e '
const { generateKeyPairSync, randomBytes } = require("crypto");
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
process.stdout.write(JSON.stringify({ type: "service_account", project_id: "check-project", private_key_id: randomBytes(20).toString("hex"),
  private_key: privateKey.export({ type: "pkcs8", format: "pem" }), client_email: "gsc-check@check-project.iam.gserviceaccount.com",
  token_uri: "https://oauth2.googleapis.com/token" }));' > "$WORK/key.json"

dc up -d --build --quiet-pull >/dev/null 2>&1 || { dc up -d --build; exit 1; }
for service in gsc-mcp egress ingress; do
  for _ in $(seq 1 60); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$PROJECT-$service-1" 2>/dev/null)" = healthy ] && break
    sleep 1
  done
  check "Container $service gesund" "$(docker inspect -f '{{.State.Health.Status}}' "$PROJECT-$service-1")" healthy
done

echo '--- Image'
docker run --rm --entrypoint /bin/sh gsc-mcp:local -c true >/dev/null 2>&1 && bad 'Image enthält /bin/sh' || ok 'Image ohne Shell'
check 'Code gehört root' "$(docker run --rm --entrypoint /nodejs/bin/node gsc-mcp:local -e 'process.stdout.write(String(require("fs").statSync("/app/dist/http.js").uid))')" 0

echo '--- Container'
for service in gsc-mcp egress ingress; do
  c="$PROJECT-$service-1"
  check "$service: Nutzer" "$(docker inspect -f '{{.Config.User}}' "$c")" 65532:65532
  check "$service: Dateisystem schreibgeschützt" "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$c")" true
  check "$service: Capabilities" "$(docker inspect -f '{{.HostConfig.CapDrop}} {{len .HostConfig.CapAdd}}' "$c")" '[ALL] 0'
  check "$service: no-new-privileges" "$(docker inspect -f '{{.HostConfig.SecurityOpt}}' "$c")" '[no-new-privileges:true]'
  docker inspect -f '{{join .Args " "}}' "$c" | grep -q -- '--permission --disallow-code-generation-from-strings' && ok "$service: Permission Model" || bad "$service: Permission Model fehlt"
done
check 'Server nur am internen Netz' "$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$PROJECT-gsc-mcp-1")" "${PROJECT}_internal "
check 'Netz internal ohne Internet' "$(docker network inspect -f '{{.Internal}}' "${PROJECT}_internal")" true
check 'Port nur auf 127.0.0.1' "$(docker port "$PROJECT-ingress-1" 3001/tcp)" "127.0.0.1:$PORT"

echo '--- Verwaltung'
dc run --rm -T gsc-admin tenant add kunde-a < "$WORK/key.json" >/dev/null 2>&1 && ok 'tenant add' || bad 'tenant add'
TOKEN=$(dc run --rm -T gsc-admin token add --user anna --tenant kunde-a --property sc-domain:kunde-a.example 2>/dev/null)
[[ "$TOKEN" =~ ^gsc_[A-Za-z0-9_-]{43}$ ]] && ok 'token add' || bad 'token add'
docker exec "$PROJECT-gsc-mcp-1" /nodejs/bin/node -e 'try { require("fs").writeFileSync("/config/x", "1"); process.stdout.write("schreibbar") } catch (e) { process.stdout.write(e.code) }' > "$WORK/w"
check 'Server kann Freigaben nicht ändern' "$(cat "$WORK/w")" EROFS

echo '--- Zugang über die Weiterleitung'
URL=http://127.0.0.1:$PORT
call() {
  curl -s -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -H "Authorization: Bearer $1" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3}}" "$URL/mcp"
}
check '/health' "$(curl -s "$URL/health")" '{"status":"ok"}'
check '/mcp ohne Token' "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL/mcp")" 401
check 'anderer Pfad' "$(curl -s -o /dev/null -w '%{http_code}' "$URL/admin")" 404
call "$TOKEN" gsc_whoami '{}' | grep -q '\\"tenant\\": \\"kunde-a\\"' && ok 'gsc_whoami' || bad 'gsc_whoami'
call "$TOKEN" gsc_list_sitemaps '{"property":"sc-domain:kunde-b.example"}' | grep -q 'Property nicht verfügbar' && ok 'fremde Property abgelehnt' || bad 'fremde Property'

echo '--- Egress'
docker exec "$PROJECT-gsc-mcp-1" /nodejs/bin/node -e '
fetch("https://example.com/", { signal: AbortSignal.timeout(5000) }).then(() => process.stdout.write("erreichbar"), () => process.stdout.write("gesperrt"));' > "$WORK/e"
check 'Server erreicht das Internet nicht direkt' "$(cat "$WORK/e")" gesperrt
connect_via_proxy() {
  docker exec "$PROJECT-gsc-mcp-1" /nodejs/bin/node -e '
const s = require("net").connect(3128, "egress", () => s.write(`CONNECT ${process.argv[1]} HTTP/1.1\r\nHost: ${process.argv[1]}\r\n\r\n`));
s.once("data", (d) => { process.stdout.write(d.toString().split(" ")[1]); s.destroy(); });
s.on("error", () => process.stdout.write("fehler"));' "$1"
}
check 'Proxy: example.com gesperrt' "$(connect_via_proxy example.com:443)" 403
check 'Proxy: Metadaten-Adresse gesperrt' "$(connect_via_proxy 169.254.169.254:80)" 403
check 'Proxy: oauth2.googleapis.com erlaubt' "$(connect_via_proxy oauth2.googleapis.com:443)" 200
check 'Proxy: searchconsole.googleapis.com erlaubt' "$(connect_via_proxy searchconsole.googleapis.com:443)" 200

echo '--- Audit-Log'
docker run --rm -v "${PROJECT}_audit_data:/d:ro" --entrypoint /nodejs/bin/node gsc-mcp:local -e '
const fs = require("fs");
const text = fs.readdirSync("/d/audit").map((f) => fs.readFileSync("/d/audit/" + f, "utf8")).join("");
process.stdout.write(/gsc_[A-Za-z0-9_-]{43}|PRIVATE KEY|[0-9a-f]{64}/.test(text) ? "geheim" : String(text.trim().split("\n").length));' > "$WORK/a"
[ "$(cat "$WORK/a")" != geheim ] && [ "$(cat "$WORK/a")" -ge 4 ] && ok "Audit-Log: $(cat "$WORK/a") Einträge, ohne Token, Hash oder Schlüssel" || bad "Audit-Log: $(cat "$WORK/a")"

if [ "$fails" -gt 0 ]; then
  echo "$fails Prüfung(en) fehlgeschlagen"
  dc logs --tail 20 || true
  exit 1
fi
echo 'Alle Prüfungen bestanden.'

#!/usr/bin/env node
/**
 * Rauchtest gegen die echte Search Console, mit dem Schlüssel eines Service Accounts.
 * Prüft, was nur mit echtem Zugang geht: Anmeldung, Properties, Leistungsdaten, Sitemaps und die
 * URL-Prüfung (offen ist, ob Google sie für die Berechtigung „Eingeschränkt“ freigibt).
 *
 *   node scripts/smoke-google.ts <schluessel.json> <property> [url-fuer-die-pruefung]
 *
 * Läuft lokal auf dem eigenen Rechner, ohne Server und ohne Tokens. Gibt nur Zusammenfassungen aus,
 * keine Suchanfragen und keine Schlüssel. Ändert nichts bei Google.
 */
import { readFile } from 'node:fs/promises';
import { GoogleClients, GoogleError, parseServiceAccountKey } from '../src/google.ts';
import { propertyProblem } from '../src/tokens.ts';
import { urlInProperty } from '../src/tools.ts';

const [keyFile, property, url] = process.argv.slice(2);
if (!keyFile || !property) {
  console.error('Aufruf: node scripts/smoke-google.ts <schluessel.json> <property> [url-fuer-die-pruefung]');
  process.exit(2);
}
const problem = propertyProblem(property);
if (problem) {
  console.error(problem);
  process.exit(2);
}
if (url && !urlInProperty(url, property)) {
  console.error('Die URL gehört nicht zur Property.');
  process.exit(2);
}

const key = parseServiceAccountKey(await readFile(keyFile, 'utf8'));
const google = new GoogleClients({ keyDir: '', keyFile: () => keyFile });
const api = await google.forTenant({ name: 'smoke', serviceAccount: key.client_email });
console.log(`Service Account: ${key.client_email}`);

let failures = 0;
async function step(name: string, fn: () => Promise<string>) {
  try {
    console.log(`ok     ${name}: ${await fn()}`);
  } catch (error) {
    failures += 1;
    const e = error instanceof GoogleError ? `${error.kind} (${error.status ?? '–'}): ${error.detail}` : String(error);
    console.log(`FEHLER ${name}: ${e}`);
  }
}

const day = (offset: number) => new Date(Date.now() - offset * 86_400_000).toISOString().slice(0, 10);

await step('Anmeldung und Properties', async () => {
  const sites = (await api.listSites()).siteEntry ?? [];
  const own = sites.find((s) => s.siteUrl === property);
  return `${sites.length} Properties sichtbar; ${property}: ${own ? own.permissionLevel : 'NICHT sichtbar'}`;
});
await step('Leistungsdaten (28 Tage, Summe)', async () => {
  const response = await api.query(property, { startDate: day(30), endDate: day(3), rowLimit: 1 });
  const row = response.rows?.[0];
  return row ? `${row.clicks} Klicks, ${row.impressions} Impressionen` : 'keine Daten im Zeitraum';
});
await step('Leistungsdaten nach Suchanfrage', async () => {
  const response = await api.query(property, { startDate: day(30), endDate: day(3), dimensions: ['query'], rowLimit: 10 });
  return `${response.rows?.length ?? 0} Zeilen`;
});
await step('Sitemaps', async () => `${(await api.listSitemaps(property)).sitemap?.length ?? 0} Sitemaps`);
if (url) {
  await step('URL-Prüfung', async () => {
    const result = (await api.inspect(property, url, 'de')).inspectionResult;
    return `${result?.indexStatusResult?.verdict ?? '?'} – ${result?.indexStatusResult?.coverageState ?? '?'}`;
  });
} else {
  console.log('–      URL-Prüfung übersprungen (keine URL angegeben)');
}
process.exit(failures ? 1 : 0);

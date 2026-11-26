/** Konfiguration aus der Umgebung. Freigaben und Schlüssel stehen nicht hier, sondern in Dateien (tokens.ts, google.ts). */
export interface GscConfig {
  /** Freigabedatei (Tokens, Mandanten, Properties). Schreibt nur gsc-admin. */
  configFile: string;
  /** Verzeichnis mit den Service-Account-Schlüsseln, eine Datei <mandant>.json je Mandant */
  keyDir: string;
  /** Verzeichnis des Audit-Logs */
  auditDir: string | undefined;
  /** Aufbewahrung des Audit-Logs in Tagen (0 = unbegrenzt) */
  auditRetentionDays: number;
  /** Maximale Gesamtgröße des Audit-Logs in Bytes (0 = unbegrenzt). Ist sie erreicht, liefert der Server keine Daten mehr. */
  auditMaxBytes: number;
  /** URL-Prüfungen je Mandant und Tag (0 = unbegrenzt) */
  maxInspectionsPerDay: number;
  /** Aufrufe je Token und Minute (0 = unbegrenzt) */
  maxCallsPerMinute: number;
  /** Aufrufe je Token und Tag (0 = unbegrenzt) */
  maxCallsPerDay: number;
  /** Ausgehender Proxy für alle Anfragen an Google (Egress-Allowlist), z. B. http://egress:3128 */
  egressProxy: string | undefined;
}

/** Liest eine ganze Zahl ≥ 0 aus der Umgebung. */
export function count(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name]?.trim();
  const value = raw ? Number(raw) : fallback;
  if (!Number.isInteger(value) || value < 0) throw new Error(`${name} muss eine ganze Zahl ≥ 0 sein.`);
  return value;
}

export function flag(value: string | undefined): boolean {
  return value !== undefined && ['1', 'true', 'yes', 'ja', 'on'].includes(value.trim().toLowerCase());
}

function proxyUrl(value: string | undefined): string | undefined {
  const raw = value?.trim();
  if (!raw) return undefined;
  const url = new URL(raw);
  if (url.protocol !== 'http:') throw new Error('GSC_EGRESS_PROXY muss mit http:// beginnen (die Verbindung zu Google bleibt trotzdem TLS-verschlüsselt).');
  if (url.username || url.password || (url.pathname !== '/' && url.pathname !== '') || url.search) throw new Error('GSC_EGRESS_PROXY: nur Host und Port angeben, z. B. http://egress:3128');
  return url.origin;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): GscConfig {
  return {
    configFile: env.GSC_CONFIG?.trim() || '/config/tokens.yaml',
    keyDir: env.GSC_KEY_DIR?.trim() || '/run/secrets/gsc',
    auditDir: env.GSC_AUDIT_DIR?.trim() || undefined,
    auditRetentionDays: count(env, 'GSC_AUDIT_RETENTION_DAYS', 365),
    auditMaxBytes: count(env, 'GSC_AUDIT_MAX_MB', 500) * 1024 * 1024,
    maxInspectionsPerDay: count(env, 'GSC_MAX_INSPECTIONS_PER_DAY', 500),
    maxCallsPerMinute: count(env, 'GSC_MAX_CALLS_PER_MINUTE', 60),
    maxCallsPerDay: count(env, 'GSC_MAX_CALLS_PER_DAY', 2000),
    egressProxy: proxyUrl(env.GSC_EGRESS_PROXY),
  };
}

/**
 * Zugang zur Search Console: je Mandant ein eigener Service Account.
 *
 * Der Schlüssel liegt als <GSC_KEY_DIR>/<mandant>.json (im Container nur lesend eingehängt). Bevor er benutzt wird,
 * muss seine client_email genau dem Service Account entsprechen, der für den Mandanten in der Freigabedatei steht.
 * So kann ein vertauschter Schlüssel keinen fremden Mandanten öffnen.
 *
 * Angefordert wird immer nur der Scope webmasters.readonly. Weiterleitungen werden nicht verfolgt.
 */
// Erster Import: schaltet das Debug-Logging der Google-Bibliotheken ab, bevor sie geladen werden
import './quiet-google.ts';
import { createPrivateKey } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { searchconsole, type searchconsole_v1 } from '@googleapis/searchconsole';
import { JWT } from 'google-auth-library';
import { SERVICE_ACCOUNT_PATTERN, TENANT_PATTERN, type Tenant } from './tokens.ts';

export const SCOPE = 'https://www.googleapis.com/auth/webmasters.readonly';
export const TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const API_ROOT = 'https://searchconsole.googleapis.com/';
/** Die beiden Ziele, die der Dienst überhaupt ansprechen muss (Egress-Allowlist). */
export const GOOGLE_HOSTS = ['oauth2.googleapis.com', 'searchconsole.googleapis.com'] as const;

const MAX_KEY_BYTES = 16 * 1024;
const KEY_CHECK_INTERVAL_MS = 5_000;

export interface ServiceAccountKey {
  client_email: string;
  private_key: string;
  private_key_id: string;
}

/** Prüft eine Schlüsseldatei. Wirft mit einer Meldung, die nie den Schlüssel selbst enthält. */
export function parseServiceAccountKey(text: string): ServiceAccountKey {
  if (Buffer.byteLength(text) > MAX_KEY_BYTES) throw new Error('Die Schlüsseldatei ist zu groß für einen Service-Account-Schlüssel.');
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error('Die Schlüsseldatei ist kein gültiges JSON.');
  }
  if (data === null || typeof data !== 'object' || Array.isArray(data)) throw new Error('Die Schlüsseldatei ist kein JSON-Objekt.');
  if (data.type !== 'service_account') throw new Error('Kein Service-Account-Schlüssel (type muss "service_account" sein).');
  const email = data.client_email;
  if (typeof email !== 'string' || !SERVICE_ACCOUNT_PATTERN.test(email)) throw new Error('client_email fehlt oder ist keine Service-Account-Adresse.');
  if (typeof data.private_key_id !== 'string' || !/^[0-9a-f]{20,64}$/.test(data.private_key_id)) throw new Error('private_key_id fehlt oder ist ungültig.');
  if (data.token_uri !== undefined && data.token_uri !== TOKEN_URL) throw new Error(`token_uri muss ${TOKEN_URL} sein.`);
  if (typeof data.private_key !== 'string') throw new Error('private_key fehlt.');
  try {
    const key = createPrivateKey(data.private_key);
    if (key.asymmetricKeyType !== 'rsa') throw new Error();
  } catch {
    throw new Error('private_key ist kein lesbarer RSA-Schlüssel.');
  }
  return { client_email: email, private_key: data.private_key, private_key_id: data.private_key_id };
}

// ---- Fehler ---------------------------------------------------------------

/** Art eines Google-Fehlers. "denied" (403/404) wird gegenüber dem Nutzer nie von "nicht freigegeben" unterschieden. */
export type GoogleErrorKind = 'denied' | 'auth' | 'quota' | 'request' | 'unavailable' | 'setup';

export class GoogleError extends Error {
  readonly kind: GoogleErrorKind;
  readonly status: number | undefined;
  /** Nur fürs Protokoll, nie für den Nutzer: Googles eigene Meldung, gekürzt. */
  readonly detail: string;

  constructor(kind: GoogleErrorKind, message: string, detail: string, status?: number) {
    super(message);
    this.kind = kind;
    this.status = status;
    this.detail = detail.slice(0, 300);
  }
}

const QUOTA_REASONS = new Set(['rateLimitExceeded', 'userRateLimitExceeded', 'quotaExceeded', 'dailyLimitExceeded', 'RATE_LIMIT_EXCEEDED', 'RESOURCE_EXHAUSTED']);

interface GaxiosLikeError {
  status?: number;
  code?: string | number;
  message?: string;
  config?: { url?: string | URL };
  response?: { status?: number; data?: any };
}

/** Ordnet einen Fehler aus gaxios/googleapis ein. */
export function classify(error: unknown): GoogleError {
  if (error instanceof GoogleError) return error;
  const e = (error ?? {}) as GaxiosLikeError;
  const status = e.response?.status ?? (typeof e.status === 'number' ? e.status : undefined);
  const data = e.response?.data;
  const googleMessage = typeof data?.error?.message === 'string' ? data.error.message : typeof data?.error_description === 'string' ? `${data.error}: ${data.error_description}` : String(e.message ?? error);
  const reasons: string[] = [data?.error?.status, ...(Array.isArray(data?.error?.errors) ? data.error.errors.map((x: any) => x?.reason) : [])].filter((x) => typeof x === 'string');
  const url = String(e.config?.url ?? '');

  if (url.startsWith(TOKEN_URL) || (typeof data?.error === 'string' && status !== undefined && status < 500)) {
    if (status === undefined || status >= 500) return new GoogleError('unavailable', 'Google ist gerade nicht erreichbar. Bitte später erneut versuchen.', googleMessage, status);
    return new GoogleError('auth', 'Die Anmeldung bei Google ist für deinen Mandanten fehlgeschlagen. Bitte den Betreiber des Servers informieren.', googleMessage, status);
  }
  if (status === 429 || (status === 403 && reasons.some((r) => QUOTA_REASONS.has(r)))) {
    return new GoogleError('quota', 'Das Kontingent bei Google ist gerade ausgeschöpft. Bitte später erneut versuchen und nicht sofort wiederholen.', googleMessage, status);
  }
  if (status === 401) return new GoogleError('auth', 'Die Anmeldung bei Google ist für deinen Mandanten fehlgeschlagen. Bitte den Betreiber des Servers informieren.', googleMessage, status);
  if (status === 403 || status === 404) return new GoogleError('denied', 'denied', googleMessage, status);
  if (status !== undefined && status >= 400 && status < 500) return new GoogleError('request', `Google lehnt die Anfrage ab: ${googleMessage.slice(0, 300)}`, googleMessage, status);
  return new GoogleError('unavailable', 'Google ist gerade nicht erreichbar. Bitte später erneut versuchen.', googleMessage, status);
}

// ---- API je Mandant ---------------------------------------------------------

export interface GoogleOptions {
  /** Verzeichnis mit <mandant>.json */
  keyDir: string;
  /** Nur für den lokalen stdio-Start: Schlüsseldatei abweichend vom Schema <keyDir>/<mandant>.json */
  keyFile?: (tenant: string) => string;
  /** Ausgehender Proxy (Egress-Allowlist), z. B. http://egress:3128 */
  proxy?: string;
  /** Nur für Tests: ersetzt den HTTP-Client (Anfragen an einen nachgebauten Google-Server umleiten). */
  fetchImplementation?: typeof fetch;
  timeoutMs?: number;
  /** Wie oft eine Schlüsseldatei höchstens auf Änderungen geprüft wird (Standard 5 s) */
  keyCheckIntervalMs?: number;
  now?: () => number;
}

export type SearchAnalyticsRequest = searchconsole_v1.Schema$SearchAnalyticsQueryRequest;

/** Die Search Console, gesehen durch den Service Account eines Mandanten. */
export class TenantApi {
  readonly tenant: string;
  readonly #api: searchconsole_v1.Searchconsole;
  readonly #options = { retryConfig: { retry: 1, noResponseRetries: 1 } };

  constructor(tenant: string, key: ServiceAccountKey, options: GoogleOptions) {
    this.tenant = tenant;
    const auth = new JWT({
      email: key.client_email,
      key: key.private_key,
      keyId: key.private_key_id,
      scopes: [SCOPE],
      transporterOptions: {
        timeout: options.timeoutMs ?? 20_000,
        maxRedirects: 0,
        ...(options.proxy ? { proxy: options.proxy } : {}),
        ...(options.fetchImplementation ? { fetchImplementation: options.fetchImplementation as never } : {}),
      },
    });
    this.#api = searchconsole({ version: 'v1', auth });
  }

  async #call<T>(fn: () => Promise<{ data: T }>): Promise<T> {
    try {
      return (await fn()).data;
    } catch (error) {
      throw classify(error);
    }
  }

  listSites() {
    return this.#call(() => this.#api.sites.list({}, this.#options));
  }

  query(siteUrl: string, requestBody: SearchAnalyticsRequest) {
    return this.#call(() => this.#api.searchanalytics.query({ siteUrl, requestBody }, this.#options));
  }

  listSitemaps(siteUrl: string, sitemapIndex?: string) {
    return this.#call(() => this.#api.sitemaps.list({ siteUrl, sitemapIndex }, this.#options));
  }

  getSitemap(siteUrl: string, feedpath: string) {
    return this.#call(() => this.#api.sitemaps.get({ siteUrl, feedpath }, this.#options));
  }

  inspect(siteUrl: string, inspectionUrl: string, languageCode?: string) {
    return this.#call(() => this.#api.urlInspection.index.inspect({ requestBody: { siteUrl, inspectionUrl, languageCode } }, this.#options));
  }
}

/**
 * Liefert je Mandant einen API-Zugang mit dessen eigenem Schlüssel. Schlüssel werden bei Bedarf geladen und
 * neu geladen, wenn sich die Datei oder der eingetragene Service Account ändert (Schlüsselwechsel ohne Neustart).
 */
export class GoogleClients {
  readonly #options: GoogleOptions;
  readonly #now: () => number;
  readonly #cache = new Map<string, { signature: string; checkedAt: number; api: TenantApi }>();

  constructor(options: GoogleOptions) {
    this.#options = options;
    this.#now = options.now ?? Date.now;
  }

  keyFile(tenant: string): string {
    if (!TENANT_PATTERN.test(tenant)) throw new Error(`Ungültiger Mandantenname: ${tenant}`);
    if (this.#options.keyFile) return this.#options.keyFile(tenant);
    return join(this.#options.keyDir, `${tenant}.json`);
  }

  async forTenant(tenant: Tenant): Promise<TenantApi> {
    const cached = this.#cache.get(tenant.name);
    const now = this.#now();
    if (cached && now - cached.checkedAt < (this.#options.keyCheckIntervalMs ?? KEY_CHECK_INTERVAL_MS) && cached.signature.startsWith(`${tenant.serviceAccount}:`)) return cached.api;

    const file = this.keyFile(tenant.name);
    let signature: string;
    try {
      const info = await stat(file);
      signature = `${tenant.serviceAccount}:${info.ino}:${info.size}:${info.mtimeMs}`;
    } catch {
      this.#cache.delete(tenant.name);
      throw new GoogleError('setup', 'Der Google-Zugang deines Mandanten ist nicht eingerichtet. Bitte den Betreiber des Servers informieren.', `Schlüsseldatei fehlt: ${tenant.name}.json`);
    }
    if (cached && cached.signature === signature) {
      cached.checkedAt = now;
      return cached.api;
    }

    let key: ServiceAccountKey;
    try {
      key = parseServiceAccountKey(await readFile(file, 'utf8'));
    } catch (error) {
      this.#cache.delete(tenant.name);
      throw new GoogleError('setup', 'Der Google-Zugang deines Mandanten ist nicht eingerichtet. Bitte den Betreiber des Servers informieren.', `Schlüsseldatei ${tenant.name}.json: ${(error as Error).message}`);
    }
    if (key.client_email !== tenant.serviceAccount) {
      this.#cache.delete(tenant.name);
      throw new GoogleError(
        'setup',
        'Der Google-Zugang deines Mandanten ist nicht eingerichtet. Bitte den Betreiber des Servers informieren.',
        `Schlüssel ${tenant.name}.json gehört zu einem anderen Service Account als in der Freigabedatei eingetragen`,
      );
    }
    const api = new TenantApi(tenant.name, key, this.#options);
    this.#cache.set(tenant.name, { signature, checkedAt: now, api });
    return api;
  }
}

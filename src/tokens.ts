/**
 * Freigaben: welche Tokens es gibt, zu welchem Mandanten sie gehören und welche Properties sie abfragen dürfen.
 *
 * Gespeichert in einer YAML-Datei (Standard /config/tokens.yaml), die nur gsc-admin schreibt.
 * Von einem Token liegt dort nur der SHA-256-Hash. Der Dienst liest die Datei bei jeder Änderung neu;
 * ist sie fehlerhaft, lehnt er alle Anfragen ab, statt mit einem veralteten Stand weiterzuarbeiten.
 */
import { createHash, randomBytes } from 'node:crypto';
import { open, readFile, rename, rm, stat } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { parse, stringify } from 'yaml';
import * as z from 'zod';

/** Token: "gsc_" und 32 Zufallsbytes in base64url (43 Zeichen). */
export const TOKEN_PATTERN = /^gsc_[A-Za-z0-9_-]{43}$/;
export const TENANT_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export const USER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$/;
export const TOKEN_ID_PATTERN = /^t_[0-9a-f]{12}$/;
/** E-Mail eines Service Accounts: <name>@<projekt>.iam.gserviceaccount.com */
export const SERVICE_ACCOUNT_PATTERN = /^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/;

const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_FILE_BYTES = 1024 * 1024;

/**
 * Prüft, ob eine Property in der Schreibweise der Search Console angegeben ist.
 * Die Whitelist vergleicht exakt; eine abweichende Schreibweise würde nie passen.
 * Liefert eine Fehlermeldung oder undefined.
 */
export function propertyProblem(value: string): string | undefined {
  if (value.startsWith('sc-domain:')) {
    if (DOMAIN_PATTERN.test(value.slice('sc-domain:'.length))) return undefined;
    return `"${value}": Domain-Property als "sc-domain:" plus Domain in Kleinbuchstaben angeben, z. B. sc-domain:example.com`;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return `"${value}": erwartet wird "sc-domain:<domain>" oder eine URL-Präfix-Property wie https://www.example.com/`;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return `"${value}": URL-Präfix-Properties beginnen mit https:// oder http://`;
  if (url.username || url.password || url.search || url.hash) return `"${value}": ohne Zugangsdaten, Query und Fragment angeben`;
  const canonical = url.href.endsWith('/') ? url.href : `${url.href}/`;
  if (value !== canonical) return `"${value}": in der Schreibweise der Search Console angeben: ${canonical}`;
  return undefined;
}

// ---- Dateiformat ----------------------------------------------------------

const propertySchema = z
  .string()
  .max(512)
  .refine((value) => propertyProblem(value) === undefined, { error: (issue) => propertyProblem(String(issue.input)) ?? 'ungültige Property' });

const tenantSchema = z.strictObject({
  service_account: z.string().regex(SERVICE_ACCOUNT_PATTERN, 'erwartet wird die E-Mail des Service Accounts (…@<projekt>.iam.gserviceaccount.com)'),
});

const tokenSchema = z.strictObject({
  id: z.string().regex(TOKEN_ID_PATTERN),
  user: z.string().regex(USER_PATTERN),
  tenant: z.string().regex(TENANT_PATTERN),
  properties: z.array(propertySchema).min(1).max(1000),
  token_sha256: z.string().regex(/^[0-9a-f]{64}$/),
  created: z.string().max(40).optional(),
});

const fileSchema = z.strictObject({
  version: z.literal(1),
  tenants: z.preprocess((value) => value ?? {}, z.record(z.string().regex(TENANT_PATTERN, 'Mandantenname: Kleinbuchstaben, Ziffern und "-"'), tenantSchema)),
  tokens: z.preprocess((value) => value ?? [], z.array(tokenSchema)),
});

export type ConfigFile = z.infer<typeof fileSchema>;
export type TokenRecord = ConfigFile['tokens'][number];

export interface Tenant {
  name: string;
  serviceAccount: string;
}

export interface Identity {
  tokenId: string;
  user: string;
  tenant: string;
  properties: readonly string[];
}

export interface Snapshot {
  tenants: ReadonlyMap<string, Tenant>;
  /** SHA-256 (hex) eines Tokens → Freigabe */
  byHash: ReadonlyMap<string, Identity>;
}

export const EMPTY_CONFIG: ConfigFile = { version: 1, tenants: {}, tokens: [] };

export class ConfigError extends Error {}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function generateToken(): string {
  return `gsc_${randomBytes(32).toString('base64url')}`;
}

export function generateTokenId(): string {
  return `t_${randomBytes(6).toString('hex')}`;
}

/** Liest und prüft den Inhalt der Freigabedatei. Wirft ConfigError mit einer lesbaren Begründung. */
export function parseConfig(text: string): ConfigFile {
  let raw: unknown;
  try {
    // Nur das YAML-Core-Schema, keine Aliase (Schutz vor "Billion Laughs"), doppelte Schlüssel sind ein Fehler
    raw = parse(text, { schema: 'core', merge: false, maxAliasCount: 0, uniqueKeys: true, prettyErrors: true });
  } catch (error) {
    throw new ConfigError(`YAML-Fehler: ${error instanceof Error ? error.message : String(error)}`);
  }
  const result = fileSchema.safeParse(raw ?? EMPTY_CONFIG);
  if (!result.success) {
    const issue = result.error.issues[0];
    throw new ConfigError(`${issue.path.join('.') || '(Datei)'}: ${issue.message}`);
  }
  const config = result.data;
  // Ein Service Account gehört genau einem Mandanten: sonst wäre die Trennung bei Google aufgehoben
  const accounts = new Map<string, string>();
  for (const [name, tenant] of Object.entries(config.tenants)) {
    const other = accounts.get(tenant.service_account);
    if (other) throw new ConfigError(`Mandanten "${other}" und "${name}" nutzen denselben Service Account. Jeder Mandant braucht einen eigenen.`);
    accounts.set(tenant.service_account, name);
  }
  const ids = new Set<string>();
  const hashes = new Set<string>();
  for (const token of config.tokens) {
    if (!Object.hasOwn(config.tenants, token.tenant)) throw new ConfigError(`Token ${token.id}: Mandant "${token.tenant}" ist nicht angelegt.`);
    if (ids.has(token.id)) throw new ConfigError(`Token-ID ${token.id} kommt doppelt vor.`);
    if (hashes.has(token.token_sha256)) throw new ConfigError(`Token ${token.id}: derselbe Token-Hash kommt doppelt vor.`);
    if (new Set(token.properties).size !== token.properties.length) throw new ConfigError(`Token ${token.id}: eine Property steht doppelt in der Liste.`);
    ids.add(token.id);
    hashes.add(token.token_sha256);
  }
  return config;
}

export function snapshotOf(config: ConfigFile): Snapshot {
  const tenants = new Map<string, Tenant>();
  for (const [name, tenant] of Object.entries(config.tenants)) tenants.set(name, { name, serviceAccount: tenant.service_account });
  const byHash = new Map<string, Identity>();
  for (const token of config.tokens) {
    byHash.set(token.token_sha256, { tokenId: token.id, user: token.user, tenant: token.tenant, properties: Object.freeze([...token.properties]) });
  }
  return { tenants, byHash };
}

const HEADER = `# Freigaben für gsc-mcp. Verwaltet mit gsc-admin, siehe README.
# Von einem Token steht hier nur der SHA-256-Hash. Properties werden exakt verglichen.
`;

export function serializeConfig(config: ConfigFile): string {
  return HEADER + stringify(config, { lineWidth: 0 });
}

/** Liest die Datei; fehlt sie, gilt eine leere Konfiguration (niemand hat Zugang). */
export async function readConfigFile(file: string): Promise<ConfigFile> {
  let text: string;
  try {
    const info = await stat(file);
    if (info.size > MAX_FILE_BYTES) throw new ConfigError(`Die Freigabedatei ist größer als ${MAX_FILE_BYTES / 1024} kB.`);
    text = await readFile(file, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return structuredClone(EMPTY_CONFIG);
    throw error;
  }
  return parseConfig(text);
}

/** Schreibt die Datei atomar: erst eine temporäre Datei, dann umbenennen. Leser sehen nie einen halben Stand. */
export async function writeConfigFile(file: string, config: ConfigFile): Promise<void> {
  const text = serializeConfig(config);
  parseConfig(text); // nie eine Datei schreiben, die der Dienst nicht lesen könnte
  const temp = join(dirname(file), `.${basename(file)}.${randomBytes(4).toString('hex')}.tmp`);
  const handle = await open(temp, 'wx', 0o600);
  try {
    await handle.writeFile(text, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temp, file);
  } catch (error) {
    await rm(temp, { force: true });
    throw error;
  }
}

/**
 * Hält den aktuellen Stand der Freigabedatei. Prüft höchstens einmal pro `checkIntervalMs`, ob sich die Datei
 * geändert hat (Inode, Größe, Änderungszeit), und liest sie dann neu. Ein Widerruf wirkt so nach spätestens
 * einer Sekunde, ohne Neustart.
 */
export class TokenStore {
  readonly file: string;
  readonly #intervalMs: number;
  readonly #now: () => number;
  readonly #log: (message: string) => void;
  #snapshot: Snapshot | undefined;
  #error: string | undefined;
  #signature = '';
  #checkedAt = -Infinity;
  #pending: Promise<void> | undefined;

  private constructor(file: string, options: { checkIntervalMs?: number; now?: () => number; log?: (message: string) => void }) {
    this.file = file;
    this.#intervalMs = options.checkIntervalMs ?? 1000;
    this.#now = options.now ?? Date.now;
    this.#log = options.log ?? (() => {});
  }

  /** Öffnet die Datei. Ist sie beim Start fehlerhaft, wirft open(): der Dienst startet dann nicht. */
  static async open(file: string, options: { checkIntervalMs?: number; now?: () => number; log?: (message: string) => void } = {}): Promise<TokenStore> {
    const store = new TokenStore(file, options);
    await store.#check();
    if (store.#error) throw new ConfigError(`${file}: ${store.#error}`);
    return store;
  }

  /** Aktueller Stand. Wirft ConfigError, solange die Datei fehlerhaft ist. */
  async current(): Promise<Snapshot> {
    if (this.#now() - this.#checkedAt >= this.#intervalMs) {
      this.#pending ??= this.#check().finally(() => (this.#pending = undefined));
      await this.#pending;
    }
    if (this.#error !== undefined || !this.#snapshot) throw new ConfigError('Die Freigabedatei ist fehlerhaft.');
    return this.#snapshot;
  }

  async #check(): Promise<void> {
    this.#checkedAt = this.#now();
    let signature: string;
    try {
      const info = await stat(this.file);
      signature = `${info.ino}:${info.size}:${info.mtimeMs}`;
    } catch (error) {
      signature = (error as NodeJS.ErrnoException).code === 'ENOENT' ? 'missing' : `error:${(error as Error).message}`;
    }
    if (signature === this.#signature) return;
    this.#signature = signature;
    try {
      const snapshot = snapshotOf(await readConfigFile(this.file));
      const first = this.#snapshot === undefined && this.#error === undefined;
      this.#snapshot = snapshot;
      this.#error = undefined;
      this.#log(`[gsc-mcp] Freigaben ${first ? 'geladen' : 'neu geladen'}: ${snapshot.byHash.size} Tokens, ${snapshot.tenants.size} Mandanten${signature === 'missing' ? ` (${this.file} fehlt noch)` : ''}`);
    } catch (error) {
      this.#error = error instanceof Error ? error.message : String(error);
      this.#log(`[gsc-mcp] Freigabedatei fehlerhaft, alle Anfragen werden abgelehnt: ${this.#error}`);
    }
  }
}

/**
 * Audit-Log: jeder Tool-Aufruf und jede Änderung über gsc-admin wird protokolliert.
 *
 * Format: JSON Lines, eine Datei pro Monat (YYYY-MM.jsonl), nur anhängend, Rechte 0600.
 * Protokolliert werden wer, was, welche Property, mit welchen Parametern und mit welchem Ergebnis –
 * nie der Token, sein Hash, ein Schlüssel oder die von Google gelieferten Daten.
 */
import { appendFile, chmod, mkdir, readdir, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';

export type AuditResult = 'ok' | 'denied' | 'error';

export interface CallEntry {
  user: string;
  tenant: string;
  tokenId: string;
  tool: string;
  property?: string;
  params?: Record<string, unknown>;
  result: AuditResult;
  /** Interner Grund, nie an den Nutzer: whitelist, google_403, google_404, limit, … */
  reason?: string;
  /** Interne Fehlermeldung (gekürzt), z. B. Googles eigene Meldung */
  detail?: string;
  rows?: number;
  ms: number;
}

export interface AdminEntry {
  actor: 'gsc-admin';
  action: string;
  [key: string]: unknown;
}

const FILE_PATTERN = /^(\d{4})-(\d{2})\.jsonl$/;
const DEFAULT_MAX_BYTES = 500 * 1024 * 1024;
const DAY_MS = 86_400_000;
const MAX_STRING = 120;
const MAX_LIST = 10;
/** Obergrenze je Zeile: längere Parameter werden weggelassen, damit das Log nicht mit wenigen Aufrufen vollläuft */
const MAX_LINE_BYTES = 2048;

function monthFile(time: Date): string {
  return `${time.getUTCFullYear()}-${String(time.getUTCMonth() + 1).padStart(2, '0')}.jsonl`;
}

/** Kürzt Zeichenketten und begrenzt Listen, damit eine Protokollzeile klein bleibt. */
function trim(value: unknown, depth = 0): unknown {
  if (typeof value === 'string') return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value;
  if (Array.isArray(value)) return value.slice(0, MAX_LIST).map((v) => trim(v, depth + 1));
  if (value && typeof value === 'object' && depth < 4) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) if (v !== undefined) out[k] = trim(v, depth + 1);
    return out;
  }
  return value;
}

export class AuditFullError extends Error {}

export class AuditLog {
  readonly dir: string;
  readonly #retentionDays: number;
  readonly #maxBytes: number;
  readonly #now: () => Date;
  readonly #warn: (message: string) => void;
  #warned = false;
  #queue: Promise<void> = Promise.resolve();
  #pruneTimer: NodeJS.Timeout | undefined;
  #bytes = 0;

  private constructor(dir: string, retentionDays: number, maxBytes: number, now: () => Date, warn: (message: string) => void) {
    this.dir = dir;
    this.#retentionDays = retentionDays;
    this.#maxBytes = maxBytes;
    this.#now = now;
    this.#warn = warn;
  }

  /** Legt das Verzeichnis an, prüft die Schreibbarkeit und räumt alte Monatsdateien auf. */
  static async open(
    dir: string,
    options: { retentionDays?: number; maxBytes?: number; now?: () => Date; prune?: boolean; warn?: (message: string) => void } = {},
  ): Promise<AuditLog> {
    const log = new AuditLog(dir, options.retentionDays ?? 365, options.maxBytes ?? DEFAULT_MAX_BYTES, options.now ?? (() => new Date()), options.warn ?? (() => {}));
    await mkdir(dir, { recursive: true, mode: 0o700 });
    await chmod(dir, 0o700).catch(() => {});
    await log.#append(log.#now(), ''); // schlägt hier fehl, wenn das Verzeichnis nicht beschreibbar ist
    for (const name of await log.#files()) await chmod(join(dir, name), 0o600).catch(() => {});
    if (options.prune !== false) {
      await log.prune();
      log.#pruneTimer = setInterval(() => void log.prune().catch(() => {}), DAY_MS);
      log.#pruneTimer.unref();
    }
    await log.#measure();
    return log;
  }

  close(): void {
    clearInterval(this.#pruneTimer);
  }

  /** true, wenn das Protokoll seine Maximalgröße erreicht hat. Dann gibt der Server keine Daten mehr heraus. */
  get full(): boolean {
    return this.#maxBytes > 0 && this.#bytes >= this.#maxBytes;
  }

  #append(time: Date, line: string): Promise<void> {
    const file = join(this.dir, monthFile(time));
    const write = this.#queue.then(async () => {
      await appendFile(file, line, { mode: 0o600 });
      this.#bytes += Buffer.byteLength(line);
      this.#checkFill();
    });
    this.#queue = write.catch(() => {});
    return write;
  }

  /** Meldet einmal, wenn 80 % der Maximalgröße erreicht sind; danach wieder, wenn es nach dem Aufräumen erneut so weit ist. */
  #checkFill(): void {
    if (this.#maxBytes <= 0) return;
    const high = this.#bytes >= this.#maxBytes * 0.8;
    if (high && !this.#warned) {
      this.#warn(`[gsc-mcp] Das Audit-Log ist zu ${Math.round((this.#bytes / this.#maxBytes) * 100)} % voll (GSC_AUDIT_MAX_MB). Ist es voll, liefert der Dienst keine Daten mehr.`);
    }
    this.#warned = high;
  }

  async #write(data: object): Promise<void> {
    const time = this.#now();
    const entry: Record<string, unknown> = { v: 1, time: time.toISOString(), ...(trim(data) as object) };
    let line = JSON.stringify(entry);
    if (Buffer.byteLength(line) > MAX_LINE_BYTES) {
      entry.params = { omitted: true, bytes: Buffer.byteLength(JSON.stringify(entry.params ?? null)) };
      if (typeof entry.detail === 'string') entry.detail = entry.detail.slice(0, 120);
      line = JSON.stringify(entry);
    }
    await this.#append(time, `${line}\n`);
  }

  /** Protokolliert einen Tool-Aufruf. Schlägt das fehl, darf der Aufruf keine Daten liefern. */
  call(entry: CallEntry): Promise<void> {
    if (this.full) return Promise.reject(new AuditFullError('Das Audit-Log hat seine Maximalgröße erreicht.'));
    return this.#write({ kind: 'call', ...entry });
  }

  admin(entry: AdminEntry): Promise<void> {
    return this.#write({ kind: 'admin', ...entry });
  }

  async #files(): Promise<string[]> {
    return (await readdir(this.dir)).filter((name) => FILE_PATTERN.test(name)).sort();
  }

  async #measure(): Promise<void> {
    await this.#queue;
    let total = 0;
    for (const name of await this.#files()) total += (await stat(join(this.dir, name)).catch(() => undefined))?.size ?? 0;
    this.#bytes = total;
    this.#checkFill();
  }

  /** Löscht Monatsdateien, die vollständig älter als die Aufbewahrungsfrist sind. */
  async prune(): Promise<void> {
    if (this.#retentionDays <= 0) return;
    const cutoff = this.#now().getTime() - this.#retentionDays * DAY_MS;
    for (const name of await this.#files()) {
      const match = FILE_PATTERN.exec(name)!;
      const endOfMonth = Date.UTC(Number(match[1]), Number(match[2]), 1);
      if (endOfMonth <= cutoff) await rm(join(this.dir, name), { force: true });
    }
    await this.#measure();
  }
}

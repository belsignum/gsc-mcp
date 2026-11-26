/**
 * Zugangsprüfung am Eingang des HTTP-Servers: Bearer-Token lesen, Fehlversuche je IP-Adresse begrenzen.
 *
 * Ob ein Token gültig ist, entscheidet allein die Freigabedatei (tokens.ts). Sie enthält nur SHA-256-Hashes.
 */
import { isIPv4, isIPv6 } from 'node:net';
import { TOKEN_PATTERN } from './tokens.ts';

/** Liest den Token aus "Authorization: Bearer <token>". Nicht wohlgeformte Werte gelten als "kein Token". */
export function bearerToken(header: string | undefined): string | undefined {
  const token = header?.match(/^Bearer +(\S+) *$/i)?.[1];
  return token && TOKEN_PATTERN.test(token) ? token : undefined;
}

/**
 * Schlüssel für das Rate-Limit: IPv4-Adressen unverändert, IPv6-Adressen auf ihr /64-Netz gekürzt
 * (ein einzelner Anschluss verfügt über mindestens ein ganzes /64 und könnte sonst beliebig viele Adressen durchwechseln).
 * Liefert undefined, wenn der Wert keine IP-Adresse ist.
 */
export function rateLimitKey(address: string | undefined): string | undefined {
  let ip = address?.trim().toLowerCase();
  if (!ip) return undefined;
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
  ip = ip.replace(/%.*$/, ''); // Zonen-ID (fe80::1%eth0)
  if (isIPv4(ip)) return ip;
  if (!isIPv6(ip)) return undefined;
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return mapped[1];
  // Eingebettete IPv4-Schreibweise am Ende (z. B. 64:ff9b::1.2.3.4) betrifft nur die hinteren 32 Bit
  const [head = '', tail = ''] = ip.replace(/:\d+\.\d+\.\d+\.\d+$/, ':0:0').split('::');
  const front = head ? head.split(':') : [];
  const back = tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...front, ...new Array<string>(Math.max(0, 8 - front.length - back.length)).fill('0'), ...back] : front;
  return `${groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, '')).join(':')}::/64`;
}

const MAX_LIMITER_ENTRIES = 10_000;

/** Begrenzt Fehlversuche pro Schlüssel (IP-Adresse) in einem festen Zeitfenster. */
export class FailureLimiter {
  readonly #max: number;
  readonly #windowMs: number;
  readonly #now: () => number;
  readonly #entries = new Map<string, { count: number; resetAt: number }>();

  constructor(options: { max?: number; windowMs?: number; now?: () => number } = {}) {
    this.#max = options.max ?? 10;
    this.#windowMs = options.windowMs ?? 5 * 60_000;
    this.#now = options.now ?? Date.now;
  }

  #count(key: string): number {
    const entry = this.#entries.get(key);
    if (!entry) return 0;
    if (entry.resetAt <= this.#now()) {
      this.#entries.delete(key);
      return 0;
    }
    return entry.count;
  }

  /** Sekunden bis zur Freigabe, oder 0 wenn nicht gesperrt. */
  blockedFor(key: string): number {
    if (this.#count(key) < this.#max) return 0;
    return Math.max(1, Math.ceil((this.#entries.get(key)!.resetAt - this.#now()) / 1000));
  }

  fail(key: string): void {
    const now = this.#now();
    const entry = this.#entries.get(key);
    if (entry && entry.resetAt > now) {
      entry.count += 1;
      return;
    }
    this.#entries.delete(key);
    if (this.#entries.size >= MAX_LIMITER_ENTRIES) {
      for (const [k, v] of this.#entries) if (v.resetAt <= now) this.#entries.delete(k);
      // Immer noch voll: nur die ältesten Einträge verwerfen. Alles zu leeren würde
      // jedem, der genug Adressen aufbringt, sämtliche Sperren auf einmal aufheben.
      for (const k of this.#entries.keys()) {
        if (this.#entries.size < MAX_LIMITER_ENTRIES * 0.9) break;
        this.#entries.delete(k);
      }
    }
    this.#entries.set(key, { count: 1, resetAt: now + this.#windowMs });
  }
}

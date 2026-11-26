/**
 * Kontingente in einem gleitenden Zeitfenster, gezählt im Arbeitsspeicher (nach einem Neustart beginnt die Zählung neu).
 *
 * - URL-Prüfungen je Mandant und Tag: Google begrenzt die URL Inspection API je Property
 *   (Stand 2026: 2000 Abrufe pro Tag, 600 pro Minute). Ein Agent in einer Schleife soll das nicht aufbrauchen.
 * - Aufrufe je Token und Minute bzw. Tag: Alle Mandanten teilen sich das Kontingent des Google-Cloud-Projekts
 *   und das Audit-Log. Ein einzelner Token soll keines von beiden für alle anderen ausschöpfen können.
 */
const DAY_MS = 24 * 60 * 60_000;

export type BudgetMessage = (max: number, waitMs: number) => string;

export const INSPECTION_LIMIT: BudgetMessage = (max, waitMs) =>
  `Limit erreicht: höchstens ${max} URL-Prüfungen pro Tag für deinen Mandanten. Die nächste ist in etwa ${Math.max(1, Math.ceil(waitMs / 3_600_000))} Stunde(n) möglich. Bitte den Nutzer informieren und nicht erneut versuchen.`;

export const CALL_LIMIT: BudgetMessage = (max, waitMs) =>
  `Limit erreicht: höchstens ${max} Aufrufe pro Minute für diesen Token. Bitte etwa ${Math.max(1, Math.ceil(waitMs / 1000))} Sekunden warten und Abfragen zusammenfassen (mehr Zeilen oder Dimensionen pro Abfrage).`;

export const DAILY_LIMIT: BudgetMessage = (max, waitMs) =>
  `Limit erreicht: höchstens ${max} Aufrufe pro Tag für diesen Token. Der nächste ist in etwa ${Math.max(1, Math.ceil(waitMs / 3_600_000))} Stunde(n) möglich. Bitte den Nutzer informieren und nicht erneut versuchen.`;

export class Budget {
  readonly max: number;
  readonly #windowMs: number;
  readonly #now: () => number;
  readonly #message: BudgetMessage;
  readonly #used = new Map<string, number[]>();
  /** Schlüssel, deren Ablehnung schon gemeldet wurde (bis sie wieder unter dem Limit sind) */
  readonly #reported = new Set<string>();

  /** max: Abrufe je Schlüssel im Fenster; 0 = unbegrenzt. Standard: ein Tag, Meldung für URL-Prüfungen. */
  constructor(max: number, options: { windowMs?: number; now?: () => number; message?: BudgetMessage } = {}) {
    this.max = max;
    this.#windowMs = options.windowMs ?? DAY_MS;
    this.#now = options.now ?? Date.now;
    this.#message = options.message ?? INSPECTION_LIMIT;
  }

  /** Verbucht einen Abruf oder wirft, wenn das Kontingent im Fenster aufgebraucht ist. */
  take(key: string): void {
    if (this.max <= 0) return;
    const now = this.#now();
    const recent = (this.#used.get(key) ?? []).filter((time) => time > now - this.#windowMs);
    if (recent.length >= this.max) {
      this.#used.set(key, recent);
      const first = !this.#reported.has(key);
      this.#reported.add(key);
      throw new BudgetError(this.#message(this.max, recent[0] + this.#windowMs - now), first);
    }
    this.#reported.delete(key);
    recent.push(now);
    this.#used.set(key, recent);
  }
}

export class BudgetError extends Error {
  /** true nur für die erste Ablehnung, solange der Schlüssel über dem Limit ist: nur sie kommt ins Audit-Log */
  readonly first: boolean;
  constructor(message: string, first = true) {
    super(message);
    this.first = first;
  }
}

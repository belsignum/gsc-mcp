/**
 * Kontingent für die URL-Prüfung je Mandant.
 *
 * Google begrenzt die URL Inspection API je Property (Stand 2026: 2000 Abrufe pro Tag, 600 pro Minute).
 * Ein Agent in einer Schleife soll dieses Kontingent nicht für den ganzen Mandanten aufbrauchen.
 * Gezählt wird im Arbeitsspeicher in einem gleitenden Fenster; nach einem Neustart beginnt die Zählung neu.
 */
const DAY_MS = 24 * 60 * 60_000;

export class Budget {
  readonly max: number;
  readonly #windowMs: number;
  readonly #now: () => number;
  readonly #used = new Map<string, number[]>();

  /** max: Abrufe je Schlüssel im Fenster; 0 = unbegrenzt. */
  constructor(max: number, options: { windowMs?: number; now?: () => number } = {}) {
    this.max = max;
    this.#windowMs = options.windowMs ?? DAY_MS;
    this.#now = options.now ?? Date.now;
  }

  /** Verbucht einen Abruf oder wirft, wenn das Kontingent im Fenster aufgebraucht ist. */
  take(key: string): void {
    if (this.max <= 0) return;
    const now = this.#now();
    const recent = (this.#used.get(key) ?? []).filter((time) => time > now - this.#windowMs);
    if (recent.length >= this.max) {
      this.#used.set(key, recent);
      const hours = Math.max(1, Math.ceil((recent[0] + this.#windowMs - now) / 3_600_000));
      throw new BudgetError(
        `Limit erreicht: höchstens ${this.max} URL-Prüfungen pro Tag für deinen Mandanten. Die nächste ist in etwa ${hours} Stunde(n) möglich. Bitte den Nutzer informieren und nicht erneut versuchen.`,
      );
    }
    recent.push(now);
    this.#used.set(key, recent);
  }
}

export class BudgetError extends Error {}

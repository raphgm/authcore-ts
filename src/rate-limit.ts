export interface RateLimit {
  readonly max: number;
  readonly windowMs: number;
}

export interface RateLimitDecision {
  readonly allowed: boolean;
  readonly remaining: number;
  /** Milliseconds until the caller may try again; 0 when allowed. */
  readonly retryAfterMs: number;
}

/**
 * The limiter is asynchronous so that it can be backed by shared storage. The
 * in-memory implementation below is only correct for a single process; use
 * `PostgresRateLimiter` (or your own Redis implementation) when running several instances.
 */
export interface RateLimiter {
  consume(key: string, limit: RateLimit): Promise<RateLimitDecision>;
}

interface Window {
  count: number;
  resetAt: number;
}

export class MemoryRateLimiter implements RateLimiter {
  readonly #windows = new Map<string, Window>();
  readonly #now: () => number;
  #calls = 0;

  constructor(now: () => number = Date.now) {
    this.#now = now;
  }

  consume(key: string, { max, windowMs }: RateLimit): Promise<RateLimitDecision> {
    const now = this.#now();
    this.#prune(now);

    let window = this.#windows.get(key);
    if (!window || window.resetAt <= now) {
      window = { count: 0, resetAt: now + windowMs };
      this.#windows.set(key, window);
    }
    window.count += 1;

    const allowed = window.count <= max;
    return Promise.resolve({
      allowed,
      remaining: Math.max(0, max - window.count),
      retryAfterMs: allowed ? 0 : window.resetAt - now,
    });
  }

  // Without this, every distinct key ever seen stays in memory for the life of the process.
  #prune(now: number): void {
    this.#calls += 1;
    if (this.#calls % 500 !== 0) return;
    for (const [key, window] of this.#windows) {
      if (window.resetAt <= now) this.#windows.delete(key);
    }
  }
}

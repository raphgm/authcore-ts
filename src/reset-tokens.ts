import { createHash, randomBytes } from "node:crypto";

export interface ResetTokenStore {
  insert(record: { tokenHash: string; userId: string; expiresAt: Date }): Promise<void>;
  /** Marks every unused token for the user as used, so only the newest link works. */
  invalidateForUser(userId: string, now: Date): Promise<void>;
  /**
   * Atomically marks an unused, unexpired token as used and returns its user, or
   * returns null. Two concurrent calls with the same token must not both succeed.
   */
  consume(tokenHash: string, now: Date): Promise<{ userId: string } | null>;
}

export interface ResetTokenServiceOptions {
  ttlMs?: number;
  now?: () => Date;
}

const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

/**
 * Reset links carry a random 256-bit token. Only its SHA-256 is stored, so a leaked
 * database does not leak usable links; the token is single-use and short-lived.
 */
export class ResetTokenService {
  readonly #store: ResetTokenStore;
  readonly #ttlMs: number;
  readonly #now: () => Date;

  constructor(store: ResetTokenStore, options: ResetTokenServiceOptions = {}) {
    this.#store = store;
    this.#ttlMs = options.ttlMs ?? 30 * 60 * 1000;
    this.#now = options.now ?? (() => new Date());
  }

  async issue(userId: string): Promise<{ token: string; expiresAt: Date }> {
    const now = this.#now();
    const token = randomBytes(32).toString("base64url");
    const expiresAt = new Date(now.getTime() + this.#ttlMs);
    await this.#store.invalidateForUser(userId, now);
    await this.#store.insert({ tokenHash: sha256(token), userId, expiresAt });
    return { token, expiresAt };
  }

  consume(token: string): Promise<{ userId: string } | null> {
    return this.#store.consume(sha256(token), this.#now());
  }
}

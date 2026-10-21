import type { ResetTokenStore } from "../reset-tokens.js";
import type { AuthUser, UserStore } from "../user-store.js";

/** For tests and local development. State is lost when the process exits. */
export class MemoryUserStore<U extends AuthUser = AuthUser> implements UserStore<U> {
  readonly #users = new Map<string, U>();

  add(user: U): void {
    this.#users.set(user.id, user);
  }

  findByEmail(email: string): Promise<U | null> {
    for (const user of this.#users.values()) if (user.email === email) return Promise.resolve(user);
    return Promise.resolve(null);
  }

  findById(id: string): Promise<U | null> {
    return Promise.resolve(this.#users.get(id) ?? null);
  }

  updatePasswordHash(userId: string, passwordHash: string): Promise<void> {
    this.#update(userId, (user) => ({ ...user, passwordHash }));
    return Promise.resolve();
  }

  setPasswordAndRevokeSessions(userId: string, passwordHash: string): Promise<void> {
    this.#update(userId, (user) => ({ ...user, passwordHash, sessionVersion: user.sessionVersion + 1 }));
    return Promise.resolve();
  }

  revokeSessions(userId: string): Promise<void> {
    this.#update(userId, (user) => ({ ...user, sessionVersion: user.sessionVersion + 1 }));
    return Promise.resolve();
  }

  #update(userId: string, change: (user: U) => U): void {
    const user = this.#users.get(userId);
    if (user) this.#users.set(userId, change(user));
  }
}

interface StoredToken {
  userId: string;
  expiresAt: Date;
  usedAt: Date | null;
}

export class MemoryResetTokenStore implements ResetTokenStore {
  readonly #tokens = new Map<string, StoredToken>();

  insert({ tokenHash, userId, expiresAt }: { tokenHash: string; userId: string; expiresAt: Date }): Promise<void> {
    this.#tokens.set(tokenHash, { userId, expiresAt, usedAt: null });
    return Promise.resolve();
  }

  invalidateForUser(userId: string, now: Date): Promise<void> {
    for (const token of this.#tokens.values()) if (token.userId === userId && !token.usedAt) token.usedAt = now;
    return Promise.resolve();
  }

  // Check-and-set runs in one synchronous step, so concurrent callers cannot both win.
  consume(tokenHash: string, now: Date): Promise<{ userId: string } | null> {
    const token = this.#tokens.get(tokenHash);
    if (!token || token.usedAt || token.expiresAt <= now) return Promise.resolve(null);
    token.usedAt = now;
    return Promise.resolve({ userId: token.userId });
  }
}

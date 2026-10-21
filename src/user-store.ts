import type { SessionUser } from "./session.js";

export interface AuthUser extends SessionUser {
  readonly email: string;
  readonly passwordHash: string;
}

/**
 * The only thing the library needs from your database. Implement it for any store;
 * `MemoryUserStore` and `PostgresUserStore` are provided. Applications extend
 * `AuthUser` with their own fields (role, organisation, and so on).
 */
export interface UserStore<U extends AuthUser = AuthUser> {
  /** Receives an already-normalised (trimmed, lower-case) email. */
  findByEmail(email: string): Promise<U | null>;
  findById(id: string): Promise<U | null>;
  /** Used to upgrade a hash to a newer scheme or cost; does not touch sessions. */
  updatePasswordHash(userId: string, passwordHash: string): Promise<void>;
  /** Replaces the password and invalidates every existing session, in one step. */
  setPasswordAndRevokeSessions(userId: string, passwordHash: string): Promise<void>;
  /** Invalidates every existing session without changing the password. */
  revokeSessions(userId: string): Promise<void>;
}

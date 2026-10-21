import { checkPassword, DEFAULT_PASSWORD_POLICY, type PasswordHasher, type PasswordPolicy } from "./password.js";
import type { RateLimit, RateLimiter } from "./rate-limit.js";
import type { ResetTokenService } from "./reset-tokens.js";
import type { SessionService } from "./session.js";
import type { AuthUser, UserStore } from "./user-store.js";

export type AuditEvent =
  | { type: "sign_in"; userId: string; ip?: string }
  | { type: "sign_in_failed"; ip?: string }
  | { type: "sign_in_rate_limited"; ip?: string }
  | { type: "password_reset_requested"; userId: string }
  | { type: "password_reset"; userId: string }
  | { type: "sessions_revoked"; userId: string };

export interface AuthServiceOptions<U extends AuthUser> {
  users: UserStore<U>;
  hasher: PasswordHasher;
  sessions: SessionService<U>;
  resetTokens: ResetTokenService;
  rateLimiter: RateLimiter;
  signInLimit?: RateLimit;
  passwordPolicy?: PasswordPolicy;
  /** Audit events deliberately carry no email address, so logs hold no personal data. */
  audit?: (event: AuditEvent) => void | Promise<void>;
}

export type SignInResult<U extends AuthUser> =
  | { ok: true; user: U; token: string; expiresAt: Date; rehashed: boolean }
  | { ok: false; reason: "invalid_credentials" }
  | { ok: false; reason: "rate_limited"; retryAfterMs: number };

export type ResetPasswordResult =
  | { ok: true }
  | { ok: false; reason: "weak_password"; message: string }
  | { ok: false; reason: "invalid_token" };

export const normalizeEmail = (email: string): string => email.trim().toLowerCase();

export class AuthService<U extends AuthUser> {
  readonly #options: AuthServiceOptions<U>;
  readonly #signInLimit: RateLimit;
  readonly #policy: PasswordPolicy;

  constructor(options: AuthServiceOptions<U>) {
    this.#options = options;
    this.#signInLimit = options.signInLimit ?? { max: 8, windowMs: 60_000 };
    this.#policy = options.passwordPolicy ?? DEFAULT_PASSWORD_POLICY;
  }

  async signIn(input: { email: string; password: string; ip?: string }): Promise<SignInResult<U>> {
    const { users, hasher, sessions, rateLimiter } = this.#options;
    const email = normalizeEmail(input.email);
    const ip = input.ip === undefined ? {} : { ip: input.ip };

    const decision = await rateLimiter.consume(`signin:${input.ip ?? "unknown"}:${email}`, this.#signInLimit);
    if (!decision.allowed) {
      await this.#audit({ type: "sign_in_rate_limited", ...ip });
      return { ok: false, reason: "rate_limited", retryAfterMs: decision.retryAfterMs };
    }

    // An oversized password never reaches the database, and the response is
    // identical to a wrong password.
    const tooLong = input.password.length > this.#policy.maxLength;
    const user = tooLong ? null : await users.findByEmail(email);

    // Always spend the cost of one verification, whether or not the user exists,
    // so response time does not reveal which emails have accounts.
    const passwordOk = user ? await hasher.verify(input.password, user.passwordHash) : await hasher.verifyAbsent(input.password);

    if (!user || !user.active || !passwordOk) {
      await this.#audit({ type: "sign_in_failed", ...ip });
      return { ok: false, reason: "invalid_credentials" };
    }

    let rehashed = false;
    if (hasher.needsRehash(user.passwordHash)) {
      await users.updatePasswordHash(user.id, await hasher.hash(input.password));
      rehashed = true;
    }

    const session = await sessions.issue(user);
    await this.#audit({ type: "sign_in", userId: user.id, ...ip });
    return { ok: true, user, rehashed, ...session };
  }

  /**
   * Returns a token to put in an emailed link, or null when there is no such active
   * user. Respond identically in both cases so the endpoint does not reveal which
   * emails are registered.
   */
  async requestPasswordReset(email: string): Promise<{ user: U; token: string; expiresAt: Date } | null> {
    const user = await this.#options.users.findByEmail(normalizeEmail(email));
    if (!user?.active) return null;
    const issued = await this.#options.resetTokens.issue(user.id);
    await this.#audit({ type: "password_reset_requested", userId: user.id });
    return { user, ...issued };
  }

  async resetPassword(token: string, newPassword: string): Promise<ResetPasswordResult> {
    // Check the password first, so a typo does not burn the single-use token.
    const problem = checkPassword(newPassword, this.#policy);
    if (problem) return { ok: false, reason: "weak_password", message: problem };

    const consumed = await this.#options.resetTokens.consume(token);
    if (!consumed) return { ok: false, reason: "invalid_token" };

    // Replacing the password also revokes every session, so a stolen session cannot
    // outlive the password change that was meant to lock the thief out.
    await this.#options.users.setPasswordAndRevokeSessions(consumed.userId, await this.#options.hasher.hash(newPassword));
    await this.#audit({ type: "password_reset", userId: consumed.userId });
    return { ok: true };
  }

  async revokeSessions(userId: string): Promise<void> {
    await this.#options.users.revokeSessions(userId);
    await this.#audit({ type: "sessions_revoked", userId });
  }

  async #audit(event: AuditEvent): Promise<void> {
    await this.#options.audit?.(event);
  }
}

import { SignJWT, jwtVerify } from "jose";
import { ConfigError } from "./errors.js";

export interface SessionUser {
  readonly id: string;
  readonly active: boolean;
  /** Bumped to invalidate every outstanding session for this user at once. */
  readonly sessionVersion: number;
}

export interface SessionServiceOptions<U extends SessionUser> {
  /** At least 32 bytes. Generate one with `openssl rand -base64 48`. */
  secret: string | Uint8Array;
  findUserById: (id: string) => Promise<U | null>;
  maxAgeSeconds?: number;
  issuer?: string;
  now?: () => Date;
}

const SEVEN_DAYS = 7 * 24 * 60 * 60;

export class SessionService<U extends SessionUser> {
  readonly maxAgeSeconds: number;
  readonly #key: Uint8Array;
  readonly #issuer: string;
  readonly #now: () => Date;
  readonly #findUserById: (id: string) => Promise<U | null>;

  constructor(options: SessionServiceOptions<U>) {
    const key = typeof options.secret === "string" ? new TextEncoder().encode(options.secret) : options.secret;
    if (key.byteLength < 32) throw new ConfigError("Session secret must be at least 32 bytes.");
    this.#key = key;
    this.#issuer = options.issuer ?? "authcore-ts";
    this.#now = options.now ?? (() => new Date());
    this.maxAgeSeconds = options.maxAgeSeconds ?? SEVEN_DAYS;
    this.#findUserById = options.findUserById;
  }

  async issue(user: Pick<SessionUser, "id" | "sessionVersion">): Promise<{ token: string; expiresAt: Date }> {
    const issuedAt = Math.floor(this.#now().getTime() / 1000);
    const expiresAt = issuedAt + this.maxAgeSeconds;
    const token = await new SignJWT({ sv: user.sessionVersion })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setSubject(user.id)
      .setIssuer(this.#issuer)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(this.#key);
    return { token, expiresAt: new Date(expiresAt * 1000) };
  }

  /**
   * Resolves a token to its user, or null if the token is missing, forged, expired,
   * revoked (session version changed) or the user is inactive. Only token problems
   * count as "signed out": a failing user lookup propagates, so a database outage
   * surfaces as an error instead of silently logging everyone out.
   */
  async verify(token: string | null | undefined): Promise<U | null> {
    if (!token) return null;

    let userId: string;
    let version: number;
    try {
      const { payload } = await jwtVerify(token, this.#key, {
        algorithms: ["HS256"],
        issuer: this.#issuer,
        currentDate: this.#now(),
      });
      if (typeof payload.sub !== "string" || typeof payload["sv"] !== "number") return null;
      userId = payload.sub;
      version = payload["sv"];
    } catch {
      return null;
    }

    const user = await this.#findUserById(userId);
    if (!user?.active || user.sessionVersion !== version) return null;
    return user;
  }
}

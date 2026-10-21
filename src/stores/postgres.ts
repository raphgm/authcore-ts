import type { RateLimit, RateLimitDecision, RateLimiter } from "../rate-limit.js";
import type { ResetTokenStore } from "../reset-tokens.js";
import type { AuthUser, UserStore } from "../user-store.js";

/** The subset of `pg`'s Pool/Client that this module uses, so `pg` is not a dependency of the library. */
export interface Queryable {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;
}

/** Create these tables (or adapt them into your own migrations) before using the Postgres stores. */
export const POSTGRES_SCHEMA_SQL = `
create table if not exists auth_users (
  id text primary key,
  email text not null unique,
  password_hash text not null,
  role text not null,
  active boolean not null default true,
  session_version integer not null default 0
);

create table if not exists auth_password_resets (
  token_hash text primary key,
  user_id text not null references auth_users (id) on delete cascade,
  expires_at timestamptz not null,
  used_at timestamptz
);
create index if not exists auth_password_resets_user_idx on auth_password_resets (user_id);

create table if not exists auth_rate_limits (
  key text primary key,
  count integer not null,
  reset_at timestamptz not null
);
`;

export interface PostgresUser extends AuthUser {
  readonly role: string;
}

function text(value: unknown, column: string): string {
  if (typeof value !== "string") throw new TypeError(`Expected ${column} to be text.`);
  return value;
}

function toUser(row: Record<string, unknown>): PostgresUser {
  return {
    id: text(row["id"], "id"),
    email: text(row["email"], "email"),
    passwordHash: text(row["password_hash"], "password_hash"),
    role: text(row["role"], "role"),
    active: row["active"] === true,
    sessionVersion: Number(row["session_version"]),
  };
}

export class PostgresUserStore implements UserStore<PostgresUser> {
  readonly #db: Queryable;

  constructor(db: Queryable) {
    this.#db = db;
  }

  /** Convenience for seeding and tests; real applications usually own user creation. */
  async create(user: { id: string; email: string; passwordHash: string; role: string; active?: boolean }): Promise<void> {
    await this.#db.query(
      "insert into auth_users (id, email, password_hash, role, active) values ($1, $2, $3, $4, $5)",
      [user.id, user.email, user.passwordHash, user.role, user.active ?? true],
    );
  }

  async findByEmail(email: string): Promise<PostgresUser | null> {
    const { rows } = await this.#db.query("select * from auth_users where email = $1", [email]);
    return rows[0] ? toUser(rows[0]) : null;
  }

  async findById(id: string): Promise<PostgresUser | null> {
    const { rows } = await this.#db.query("select * from auth_users where id = $1", [id]);
    return rows[0] ? toUser(rows[0]) : null;
  }

  async updatePasswordHash(userId: string, passwordHash: string): Promise<void> {
    await this.#db.query("update auth_users set password_hash = $2 where id = $1", [userId, passwordHash]);
  }

  async setPasswordAndRevokeSessions(userId: string, passwordHash: string): Promise<void> {
    await this.#db.query(
      "update auth_users set password_hash = $2, session_version = session_version + 1 where id = $1",
      [userId, passwordHash],
    );
  }

  async revokeSessions(userId: string): Promise<void> {
    await this.#db.query("update auth_users set session_version = session_version + 1 where id = $1", [userId]);
  }
}

export class PostgresResetTokenStore implements ResetTokenStore {
  readonly #db: Queryable;

  constructor(db: Queryable) {
    this.#db = db;
  }

  async insert({ tokenHash, userId, expiresAt }: { tokenHash: string; userId: string; expiresAt: Date }): Promise<void> {
    await this.#db.query("insert into auth_password_resets (token_hash, user_id, expires_at) values ($1, $2, $3)", [
      tokenHash,
      userId,
      expiresAt,
    ]);
  }

  async invalidateForUser(userId: string, now: Date): Promise<void> {
    await this.#db.query("update auth_password_resets set used_at = $2 where user_id = $1 and used_at is null", [userId, now]);
  }

  // One conditional UPDATE is the whole check-and-set, so the database guarantees that
  // two concurrent requests with the same token cannot both succeed.
  async consume(tokenHash: string, now: Date): Promise<{ userId: string } | null> {
    const { rows } = await this.#db.query(
      "update auth_password_resets set used_at = $2 where token_hash = $1 and used_at is null and expires_at > $2 returning user_id",
      [tokenHash, now],
    );
    return rows[0] ? { userId: text(rows[0]["user_id"], "user_id") } : null;
  }
}

/** A fixed-window limiter shared by every application instance that uses the same database. */
export class PostgresRateLimiter implements RateLimiter {
  readonly #db: Queryable;

  constructor(db: Queryable) {
    this.#db = db;
  }

  // A single upsert is atomic per key, so concurrent requests are counted exactly once each.
  // The database clock is used throughout, so instances with skewed clocks agree.
  async consume(key: string, { max, windowMs }: RateLimit): Promise<RateLimitDecision> {
    const { rows } = await this.#db.query(
      `insert into auth_rate_limits (key, count, reset_at)
       values ($1, 1, now() + make_interval(secs => $2::float8 / 1000))
       on conflict (key) do update set
         count = case when auth_rate_limits.reset_at <= now() then 1 else auth_rate_limits.count + 1 end,
         reset_at = case when auth_rate_limits.reset_at <= now()
                         then now() + make_interval(secs => $2::float8 / 1000)
                         else auth_rate_limits.reset_at end
       returning count, extract(epoch from (reset_at - now())) * 1000 as retry_ms`,
      [key, windowMs],
    );
    const row = rows[0];
    const count = Number(row?.["count"]);
    const allowed = count <= max;
    return { allowed, remaining: Math.max(0, max - count), retryAfterMs: allowed ? 0 : Math.ceil(Number(row?.["retry_ms"])) };
  }
}

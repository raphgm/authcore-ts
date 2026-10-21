import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AuthService,
  PasswordHasher,
  POSTGRES_SCHEMA_SQL,
  PostgresRateLimiter,
  PostgresResetTokenStore,
  PostgresUserStore,
  ResetTokenService,
  SessionService,
} from "../src/index.js";
import { describeStoreContract } from "./contract.js";
import { SECRET } from "./helpers.js";

const url = process.env["DATABASE_URL"];
const pool = url ? new Pool({ connectionString: url, max: 30 }) : undefined;

beforeAll(async () => {
  if (!pool) return;
  await pool.query("drop table if exists auth_password_resets, auth_rate_limits, auth_users cascade");
  await pool.query(POSTGRES_SCHEMA_SQL);
});
afterAll(async () => {
  await pool?.end();
});

const requirePool = (): Pool => {
  if (!pool) throw new Error("DATABASE_URL is not set");
  return pool;
};

describeStoreContract(
  "postgres",
  () => {
    const db = requirePool();
    const users = new PostgresUserStore(db);
    return Promise.resolve({
      users,
      tokens: new PostgresResetTokenStore(db),
      limiter: new PostgresRateLimiter(db),
      seed: (user) =>
        users.create({ id: user.id, email: user.email, passwordHash: user.passwordHash ?? "hash", role: "USER", active: user.active ?? true }),
    });
  },
  { skip: !pool },
);

describe.skipIf(!pool)("AuthService on real Postgres", () => {
  it("signs in, resets the password and revokes the old session end to end", async () => {
    const db = requirePool();
    const hasher = new PasswordHasher({ cost: 4 });
    const users = new PostgresUserStore(db);
    await users.create({ id: "e2e", email: "e2e@example.test", passwordHash: await hasher.hash("correct horse 9"), role: "ADMIN" });

    const sessions = new SessionService({ secret: SECRET, findUserById: (id) => users.findById(id) });
    const service = new AuthService({
      users,
      hasher,
      sessions,
      resetTokens: new ResetTokenService(new PostgresResetTokenStore(db)),
      rateLimiter: new PostgresRateLimiter(db),
    });

    const signedIn = await service.signIn({ email: "e2e@example.test", password: "correct horse 9", ip: "5.5.5.5" });
    if (!signedIn.ok) throw new Error("sign-in failed");
    expect((await sessions.verify(signedIn.token))?.role).toBe("ADMIN");

    const reset = await service.requestPasswordReset("e2e@example.test");
    expect(await service.resetPassword(reset?.token ?? "", "brand-new-pass-2")).toEqual({ ok: true });

    expect(await sessions.verify(signedIn.token)).toBeNull();
    expect((await service.signIn({ email: "e2e@example.test", password: "brand-new-pass-2", ip: "6.6.6.6" })).ok).toBe(true);
  });
});

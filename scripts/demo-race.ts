// Can one single-use reset token be redeemed more than once if requests arrive together?
// "naive" is the common SELECT-then-UPDATE; "atomic" is PostgresResetTokenStore.consume.
// Needs DATABASE_URL (a real Postgres).
import { Pool } from "pg";
import { POSTGRES_SCHEMA_SQL, PostgresResetTokenStore, PostgresUserStore } from "../src/index.js";

const url = process.env["DATABASE_URL"];
if (!url) throw new Error("Set DATABASE_URL to run this demo.");

const CONCURRENCY = 40;
const ROUNDS = 5;
const pool = new Pool({ connectionString: url, max: CONCURRENCY });
await pool.query("drop table if exists auth_password_resets, auth_rate_limits, auth_users cascade");
await pool.query(POSTGRES_SCHEMA_SQL);
await new PostgresUserStore(pool).create({ id: "u1", email: "ada@example.test", passwordHash: "h", role: "USER" });

async function naiveConsume(tokenHash: string, now: Date): Promise<boolean> {
  const { rows } = await pool.query("select user_id from auth_password_resets where token_hash = $1 and used_at is null and expires_at > $2", [tokenHash, now]);
  if (rows.length === 0) return false;
  await pool.query("update auth_password_resets set used_at = $2 where token_hash = $1", [tokenHash, now]);
  return true;
}

const atomic = new PostgresResetTokenStore(pool);

console.log(`${CONCURRENCY} simultaneous requests redeem ONE reset token, ${ROUNDS} rounds. Successful redemptions per round:\n`);

for (const [label, consume] of [
  ["naive  (select, then update)", (hash: string, now: Date) => naiveConsume(hash, now)],
  ["atomic (one conditional UPDATE)", async (hash: string, now: Date) => (await atomic.consume(hash, now)) !== null],
] as const) {
  const wins: number[] = [];
  for (let round = 0; round < ROUNDS; round++) {
    const hash = `race-${label.slice(0, 5)}-${round}`;
    const now = new Date();
    await atomic.insert({ tokenHash: hash, userId: "u1", expiresAt: new Date(now.getTime() + 60_000) });
    const results = await Promise.all(Array.from({ length: CONCURRENCY }, () => consume(hash, now)));
    wins.push(results.filter(Boolean).length);
  }
  console.log(`${label.padEnd(33)}${wins.join(", ")}`);
}
await pool.end();

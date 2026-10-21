// Measures whether response time reveals if an email address has an account.
// "original" reproduces the sign-in logic from AssetOps: the password is only
// checked when a user was found. "authcore" is AuthService.signIn.
import bcrypt from "bcryptjs";
import {
  AuthService,
  MemoryRateLimiter,
  MemoryResetTokenStore,
  MemoryUserStore,
  PasswordHasher,
  ResetTokenService,
  SessionService,
  type AuthUser,
} from "../src/index.js";

const COST = 10; // the cost the original app used
const SAMPLES = 25;

const median = (values: number[]): number => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] ?? 0;
};

async function time(fn: () => Promise<unknown>): Promise<number> {
  const start = process.hrtime.bigint();
  await fn();
  return Number(process.hrtime.bigint() - start) / 1e6;
}

const hasher = new PasswordHasher({ cost: COST });
const passwordHash = await hasher.hash("correct horse 9");
const plainHash = await bcrypt.hash("correct horse 9", COST);

// --- original-style sign-in -------------------------------------------------
const originalUsers = new Map([["ada@example.test", { active: true, hash: plainHash }]]);
async function originalSignIn(email: string, password: string): Promise<boolean> {
  const user = originalUsers.get(email);
  return Boolean(user?.active && (await bcrypt.compare(password, user.hash)));
}

// --- authcore sign-in -------------------------------------------------------
interface DemoUser extends AuthUser {
  role: string;
}
const users = new MemoryUserStore<DemoUser>();
users.add({ id: "u1", email: "ada@example.test", passwordHash, role: "USER", active: true, sessionVersion: 0 });
const service = new AuthService<DemoUser>({
  users,
  hasher,
  sessions: new SessionService<DemoUser>({ secret: "x".repeat(40), findUserById: (id) => users.findById(id) }),
  resetTokens: new ResetTokenService(new MemoryResetTokenStore()),
  rateLimiter: new MemoryRateLimiter(),
});

let counter = 0;
const authcoreSignIn = (email: string, password: string) =>
  service.signIn({ email, password, ip: `10.0.${Math.floor(++counter / 250)}.${counter % 250}` });

async function measure(label: string, signIn: (email: string, password: string) => Promise<unknown>) {
  await signIn("ada@example.test", "warm-up"); // JIT warm-up, not measured
  const known: number[] = [];
  const unknown: number[] = [];
  for (let i = 0; i < SAMPLES; i++) {
    known.push(await time(() => signIn("ada@example.test", "wrong password")));
    unknown.push(await time(() => signIn("ghost@example.test", "wrong password")));
  }
  const k = median(known);
  const u = median(unknown);
  console.log(`${label.padEnd(9)} known email: ${k.toFixed(1).padStart(6)} ms   unknown email: ${u.toFixed(1).padStart(6)} ms   ratio: ${(k / u).toFixed(1)}x`);
}

console.log(`Median of ${SAMPLES} wrong-password attempts each, bcrypt cost ${COST}:\n`);
await measure("original", originalSignIn);
await measure("authcore", authcoreSignIn);

// Does a stolen session survive the owner resetting their password?
// "original" reproduces AssetOps: the JWT holds only the user id and getSession
// checks `active`. "authcore" is SessionService plus AuthService.resetPassword.
import { SignJWT, jwtVerify } from "jose";
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

const secret = new TextEncoder().encode("a-secret-that-is-comfortably-longer-than-32-bytes");

// --- original-style ---------------------------------------------------------
const originalDb = new Map([["u1", { active: true, passwordHash: "old-hash" }]]);
const originalToken = await new SignJWT({ uid: "u1" }).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime("7d").sign(secret);
async function originalGetSession(token: string): Promise<boolean> {
  const { payload } = await jwtVerify(token, secret);
  const user = originalDb.get(String(payload["uid"]));
  return Boolean(user?.active);
}

console.log("1. A thief steals the session token. 2. The owner resets their password.\n");
const before = await originalGetSession(originalToken);
originalDb.set("u1", { active: true, passwordHash: "new-hash" }); // what the original reset route does
const after = await originalGetSession(originalToken);
console.log(`original : token valid before reset: ${String(before)}   after reset: ${String(after)}   <- thief is still signed in`);

// --- authcore ---------------------------------------------------------------
interface DemoUser extends AuthUser {
  role: string;
}
const hasher = new PasswordHasher({ cost: 4 });
const users = new MemoryUserStore<DemoUser>();
users.add({ id: "u1", email: "ada@example.test", passwordHash: await hasher.hash("old password 1"), role: "USER", active: true, sessionVersion: 0 });
const sessions = new SessionService<DemoUser>({ secret, findUserById: (id) => users.findById(id) });
const service = new AuthService<DemoUser>({
  users,
  hasher,
  sessions,
  resetTokens: new ResetTokenService(new MemoryResetTokenStore()),
  rateLimiter: new MemoryRateLimiter(),
});

const signedIn = await service.signIn({ email: "ada@example.test", password: "old password 1", ip: "1.1.1.1" });
if (!signedIn.ok) throw new Error("sign-in failed");
const validBefore = (await sessions.verify(signedIn.token)) !== null;
const reset = await service.requestPasswordReset("ada@example.test");
await service.resetPassword(reset?.token ?? "", "new password 2");
const validAfter = (await sessions.verify(signedIn.token)) !== null;
console.log(`authcore : token valid before reset: ${String(validBefore)}   after reset: ${String(validAfter)}  <- revoked`);

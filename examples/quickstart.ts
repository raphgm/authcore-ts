// The README's quick start. It is type-checked in CI and run with `npx tsx examples/quickstart.ts`.
import {
  AuthService,
  MemoryRateLimiter,
  MemoryResetTokenStore,
  MemoryUserStore,
  PasswordHasher,
  ResetTokenService,
  SessionService,
  defineRbac,
  type AuthUser,
} from "authcore-ts";

// 1. Describe who can do what. Names are checked by the compiler.
const rbac = defineRbac({
  ADMIN: ["asset:read", "asset:write", "user:manage"],
  TECHNICIAN: ["asset:read"],
} as const);

// 2. Extend AuthUser with your own fields.
interface User extends AuthUser {
  role: "ADMIN" | "TECHNICIAN";
}

// 3. Pick storage. Swap MemoryUserStore for PostgresUserStore in production.
const hasher = new PasswordHasher(); // bcrypt cost 12
const users = new MemoryUserStore<User>();
users.add({
  id: "u1",
  email: "ada@example.com",
  passwordHash: await hasher.hash("correct horse battery"),
  role: "TECHNICIAN",
  active: true,
  sessionVersion: 0,
});

// 4. Wire the services.
const sessions = new SessionService<User>({
  secret: process.env["SESSION_SECRET"] ?? "development-only-secret-0123456789abcdef",
  findUserById: (id) => users.findById(id),
});
const auth = new AuthService<User>({
  users,
  hasher,
  sessions,
  resetTokens: new ResetTokenService(new MemoryResetTokenStore()),
  rateLimiter: new MemoryRateLimiter(),
});

// 5. Sign in, then resolve the session on later requests.
const result = await auth.signIn({ email: "ada@example.com", password: "correct horse battery", ip: "203.0.113.7" });
if (!result.ok) throw new Error(result.reason);

const user = await sessions.verify(result.token);
console.log("signed in as:", user?.email, `(${user?.role})`);
console.log("can write assets:", user ? rbac.can(user.role, "asset:write") : false);

// 6. Resetting the password signs the user out everywhere.
const reset = await auth.requestPasswordReset("ada@example.com");
await auth.resetPassword(reset?.token ?? "", "a brand new passphrase");
console.log("old session still valid after reset:", (await sessions.verify(result.token)) !== null);

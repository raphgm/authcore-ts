import type { AuthUser } from "../src/index.js";
import { PasswordHasher } from "../src/index.js";

// Cost 4 is bcrypt's minimum; it keeps the suite fast and is never used outside tests.
export const testHasher = (): PasswordHasher => new PasswordHasher({ cost: 4 });

export const SECRET = "test-secret-that-is-comfortably-longer-than-32-bytes";

export interface TestUser extends AuthUser {
  readonly role: string;
}

export const makeUser = (overrides: Partial<TestUser> = {}): TestUser => ({
  id: "u1",
  email: "ada@example.test",
  passwordHash: "x",
  role: "TECHNICIAN",
  active: true,
  sessionVersion: 0,
  ...overrides,
});

/** A controllable clock for expiry tests. */
export function fakeClock(start = new Date("2026-01-01T00:00:00Z")) {
  let current = start.getTime();
  return {
    now: () => new Date(current),
    ms: () => current,
    advance: (ms: number) => {
      current += ms;
    },
  };
}

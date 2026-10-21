import bcrypt from "bcryptjs";
import { describe, expect, it, vi } from "vitest";
import {
  AuthService,
  MemoryRateLimiter,
  MemoryResetTokenStore,
  MemoryUserStore,
  ResetTokenService,
  SessionService,
  type AuditEvent,
} from "../src/index.js";
import { fakeClock, makeUser, SECRET, testHasher, type TestUser } from "./helpers.js";

async function setup(options: { legacyHash?: boolean } = {}) {
  const clock = fakeClock();
  const hasher = testHasher();
  const users = new MemoryUserStore<TestUser>();
  const events: AuditEvent[] = [];

  const passwordHash = options.legacyHash ? await bcrypt.hash("correct horse 9", 4) : await hasher.hash("correct horse 9");
  users.add(makeUser({ passwordHash }));
  users.add(makeUser({ id: "u2", email: "off@example.test", passwordHash, active: false }));

  const sessions = new SessionService<TestUser>({
    secret: SECRET,
    findUserById: (id) => users.findById(id),
    now: clock.now,
  });
  const service = new AuthService<TestUser>({
    users,
    hasher,
    sessions,
    resetTokens: new ResetTokenService(new MemoryResetTokenStore(), { now: clock.now, ttlMs: 30 * 60_000 }),
    rateLimiter: new MemoryRateLimiter(clock.ms),
    audit: (event) => void events.push(event),
  });
  return { clock, hasher, users, sessions, service, events };
}

const creds = { email: "ada@example.test", password: "correct horse 9", ip: "1.1.1.1" };

describe("signIn", () => {
  it("signs in with valid credentials and the session resolves to the user", async () => {
    const { service, sessions } = await setup();
    const result = await service.signIn(creds);
    expect(result.ok).toBe(true);
    if (result.ok) expect((await sessions.verify(result.token))?.id).toBe("u1");
  });

  it("normalises the email before looking the user up", async () => {
    const { service } = await setup();
    expect((await service.signIn({ ...creds, email: "  ADA@Example.TEST " })).ok).toBe(true);
  });

  it("upgrades a legacy plain-bcrypt hash on successful sign-in", async () => {
    const { service, users, hasher } = await setup({ legacyHash: true });
    const result = await service.signIn(creds);
    expect(result.ok && result.rehashed).toBe(true);

    const stored = (await users.findById("u1"))?.passwordHash ?? "";
    expect(stored.startsWith("$bcrypt-sha256$v1$")).toBe(true);
    expect(await hasher.verify("correct horse 9", stored)).toBe(true);
    expect((await service.signIn({ ...creds, ip: "9.9.9.9" })).ok).toBe(true);
  });

  it("returns the same failure for a wrong password, an unknown user and an inactive user", async () => {
    const { service } = await setup();
    const wrong = await service.signIn({ ...creds, password: "wrong" });
    const unknown = await service.signIn({ ...creds, email: "ghost@example.test" });
    const inactive = await service.signIn({ ...creds, email: "off@example.test" });
    expect(wrong).toEqual({ ok: false, reason: "invalid_credentials" });
    expect(unknown).toEqual(wrong);
    expect(inactive).toEqual(wrong);
  });

  it("spends one password verification whether or not the user exists", async () => {
    const { service, hasher } = await setup();
    const verify = vi.spyOn(hasher, "verify");
    const absent = vi.spyOn(hasher, "verifyAbsent");

    await service.signIn({ ...creds, password: "wrong" });
    expect(verify).toHaveBeenCalledTimes(1);

    await service.signIn({ ...creds, email: "ghost@example.test" });
    expect(absent).toHaveBeenCalledTimes(1);
    expect(verify).toHaveBeenCalledTimes(2);
  });

  it("rejects an oversized password without querying the user store", async () => {
    const { service, users } = await setup();
    const find = vi.spyOn(users, "findByEmail");
    const result = await service.signIn({ ...creds, password: "x".repeat(5000) });
    expect(result).toEqual({ ok: false, reason: "invalid_credentials" });
    expect(find).not.toHaveBeenCalled();
  });

  it("rate limits repeated attempts per address and email, then recovers", async () => {
    const { service, clock } = await setup();
    let last: Awaited<ReturnType<typeof service.signIn>> | undefined;
    for (let i = 0; i < 9; i++) last = await service.signIn({ ...creds, password: "wrong" });
    expect(last).toMatchObject({ ok: false, reason: "rate_limited" });
    if (last && !last.ok && last.reason === "rate_limited") expect(last.retryAfterMs).toBeGreaterThan(0);

    expect((await service.signIn({ ...creds, ip: "2.2.2.2" })).ok).toBe(true);
    clock.advance(61_000);
    expect((await service.signIn(creds)).ok).toBe(true);
  });

  it("writes audit events that contain no email address", async () => {
    const { service, events } = await setup();
    await service.signIn({ ...creds, password: "wrong" });
    await service.signIn(creds);
    expect(events.map((e) => e.type)).toEqual(["sign_in_failed", "sign_in"]);
    expect(JSON.stringify(events)).not.toContain("example.test");
  });
});

describe("password reset", () => {
  it("issues a link token only for an active, existing user", async () => {
    const { service } = await setup();
    expect(await service.requestPasswordReset("ghost@example.test")).toBeNull();
    expect(await service.requestPasswordReset("off@example.test")).toBeNull();
    expect((await service.requestPasswordReset("ada@example.test"))?.token).toBeTruthy();
  });

  it("changes the password, and the token works exactly once", async () => {
    const { service } = await setup();
    const issued = await service.requestPasswordReset("ada@example.test");
    const token = issued?.token ?? "";

    expect(await service.resetPassword(token, "brand-new-pass-2")).toEqual({ ok: true });
    expect((await service.signIn({ ...creds, password: "brand-new-pass-2" })).ok).toBe(true);
    expect((await service.signIn({ ...creds, ip: "3.3.3.3" })).ok).toBe(false);
    expect(await service.resetPassword(token, "another-pass-3")).toEqual({ ok: false, reason: "invalid_token" });
  });

  it("does not burn the token when the new password is too weak", async () => {
    const { service } = await setup();
    const token = (await service.requestPasswordReset("ada@example.test"))?.token ?? "";
    expect(await service.resetPassword(token, "short")).toMatchObject({ ok: false, reason: "weak_password" });
    expect(await service.resetPassword(token, "long enough pass")).toEqual({ ok: true });
  });

  it("expires after the time to live", async () => {
    const { service, clock } = await setup();
    const token = (await service.requestPasswordReset("ada@example.test"))?.token ?? "";
    clock.advance(31 * 60_000);
    expect(await service.resetPassword(token, "long enough pass")).toEqual({ ok: false, reason: "invalid_token" });
  });

  it("makes an earlier link stop working when a newer one is requested", async () => {
    const { service } = await setup();
    const first = (await service.requestPasswordReset("ada@example.test"))?.token ?? "";
    const second = (await service.requestPasswordReset("ada@example.test"))?.token ?? "";
    expect(await service.resetPassword(first, "long enough pass")).toEqual({ ok: false, reason: "invalid_token" });
    expect(await service.resetPassword(second, "long enough pass")).toEqual({ ok: true });
  });

  it("revokes existing sessions, so a stolen session does not survive a password reset", async () => {
    const { service, sessions } = await setup();
    const signedIn = await service.signIn(creds);
    if (!signedIn.ok) throw new Error("sign-in failed");
    expect(await sessions.verify(signedIn.token)).not.toBeNull();

    const token = (await service.requestPasswordReset("ada@example.test"))?.token ?? "";
    await service.resetPassword(token, "brand-new-pass-2");
    expect(await sessions.verify(signedIn.token)).toBeNull();
  });
});

describe("revokeSessions", () => {
  it("signs a user out everywhere without changing their password", async () => {
    const { service, sessions } = await setup();
    const signedIn = await service.signIn(creds);
    if (!signedIn.ok) throw new Error("sign-in failed");
    await service.revokeSessions("u1");
    expect(await sessions.verify(signedIn.token)).toBeNull();
    expect((await service.signIn({ ...creds, ip: "4.4.4.4" })).ok).toBe(true);
  });
});

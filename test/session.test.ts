import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { ConfigError, SessionService } from "../src/index.js";
import { fakeClock, makeUser, SECRET, type TestUser } from "./helpers.js";

function setup(initial: TestUser = makeUser()) {
  const users = new Map<string, TestUser>([[initial.id, initial]]);
  const clock = fakeClock();
  const sessions = new SessionService<TestUser>({
    secret: SECRET,
    findUserById: (id) => Promise.resolve(users.get(id) ?? null),
    now: clock.now,
    maxAgeSeconds: 3600,
  });
  return { users, clock, sessions };
}

describe("SessionService", () => {
  it("issues a token that resolves back to the user", async () => {
    const { sessions } = setup();
    const { token, expiresAt } = await sessions.issue(makeUser());
    expect((await sessions.verify(token))?.id).toBe("u1");
    expect(expiresAt.toISOString()).toBe("2026-01-01T01:00:00.000Z");
  });

  it("returns null for missing, tampered and foreign-signed tokens", async () => {
    const { sessions } = setup();
    const { token } = await sessions.issue(makeUser());
    expect(await sessions.verify(undefined)).toBeNull();
    expect(await sessions.verify("")).toBeNull();
    expect(await sessions.verify(`${token}x`)).toBeNull();

    const foreign = await new SignJWT({ sv: 0 })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject("u1")
      .setIssuer("authcore-ts")
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode("another-secret-that-is-also-longer-than-32-bytes"));
    expect(await sessions.verify(foreign)).toBeNull();
  });

  it("only accepts HS256, rejecting unsigned and other-algorithm tokens", async () => {
    const { sessions } = setup();
    const unsigned = `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from(
      JSON.stringify({ sub: "u1", sv: 0, iss: "authcore-ts", exp: 4102444800 }),
    ).toString("base64url")}.`;
    expect(await sessions.verify(unsigned)).toBeNull();

    const hs512 = await new SignJWT({ sv: 0 })
      .setProtectedHeader({ alg: "HS512" })
      .setSubject("u1")
      .setIssuer("authcore-ts")
      .setExpirationTime(4102444800)
      .sign(new TextEncoder().encode(SECRET));
    expect(await sessions.verify(hs512)).toBeNull();
  });

  it("expires tokens", async () => {
    const { sessions, clock } = setup();
    const { token } = await sessions.issue(makeUser());
    clock.advance(3599_000);
    expect(await sessions.verify(token)).not.toBeNull();
    clock.advance(2_000);
    expect(await sessions.verify(token)).toBeNull();
  });

  it("is revoked when the user's session version changes, and when the user is deactivated", async () => {
    const { sessions, users } = setup();
    const { token } = await sessions.issue(makeUser());

    users.set("u1", makeUser({ sessionVersion: 1 }));
    expect(await sessions.verify(token)).toBeNull();

    const fresh = await sessions.issue(makeUser({ sessionVersion: 1 }));
    expect(await sessions.verify(fresh.token)).not.toBeNull();
    users.set("u1", makeUser({ sessionVersion: 1, active: false }));
    expect(await sessions.verify(fresh.token)).toBeNull();
  });

  it("lets a failing user lookup propagate instead of treating it as signed out", async () => {
    const sessions = new SessionService<TestUser>({
      secret: SECRET,
      findUserById: () => Promise.reject(new Error("database is down")),
    });
    const { token } = await sessions.issue(makeUser());
    await expect(sessions.verify(token)).rejects.toThrow("database is down");
  });

  it("refuses to start with a weak secret", () => {
    expect(
      () => new SessionService<TestUser>({ secret: "too short", findUserById: () => Promise.resolve(null) }),
    ).toThrow(ConfigError);
  });
});

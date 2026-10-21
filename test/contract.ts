import { describe, expect, it } from "vitest";
import type { RateLimiter, ResetTokenStore, UserStore } from "../src/index.js";

export interface StoreHarness {
  users: UserStore;
  tokens: ResetTokenStore;
  limiter: RateLimiter;
  /** Inserts a user for the test; ids and emails must be unique across calls. */
  seed(user: { id: string; email: string; passwordHash?: string; active?: boolean }): Promise<void>;
}

/**
 * One behavioural contract that every storage implementation must satisfy. Running the
 * same assertions against the in-memory stores and against real Postgres is what proves
 * they are interchangeable, including under concurrency.
 */
export function describeStoreContract(name: string, makeHarness: () => Promise<StoreHarness>, options: { skip?: boolean } = {}) {
  describe.skipIf(options.skip)(`store contract: ${name}`, () => {
    it("finds users by email and id, and returns null when absent", async () => {
      const h = await makeHarness();
      await h.seed({ id: "c1", email: "c1@example.test" });
      expect((await h.users.findByEmail("c1@example.test"))?.id).toBe("c1");
      expect((await h.users.findById("c1"))?.email).toBe("c1@example.test");
      expect(await h.users.findByEmail("nobody@example.test")).toBeNull();
      expect(await h.users.findById("nobody")).toBeNull();
    });

    it("updatePasswordHash changes the hash and leaves sessions alone", async () => {
      const h = await makeHarness();
      await h.seed({ id: "c2", email: "c2@example.test" });
      await h.users.updatePasswordHash("c2", "new-hash");
      const user = await h.users.findById("c2");
      expect(user?.passwordHash).toBe("new-hash");
      expect(user?.sessionVersion).toBe(0);
    });

    it("setPasswordAndRevokeSessions changes the hash and bumps the session version together", async () => {
      const h = await makeHarness();
      await h.seed({ id: "c3", email: "c3@example.test" });
      await h.users.setPasswordAndRevokeSessions("c3", "reset-hash");
      const user = await h.users.findById("c3");
      expect(user).toMatchObject({ passwordHash: "reset-hash", sessionVersion: 1 });
    });

    it("revokeSessions bumps the session version only", async () => {
      const h = await makeHarness();
      await h.seed({ id: "c4", email: "c4@example.test", passwordHash: "keep" });
      await h.users.revokeSessions("c4");
      await h.users.revokeSessions("c4");
      expect(await h.users.findById("c4")).toMatchObject({ passwordHash: "keep", sessionVersion: 2 });
    });

    it("reset tokens are single-use and respect expiry", async () => {
      const h = await makeHarness();
      await h.seed({ id: "c5", email: "c5@example.test" });
      const now = new Date();
      const later = new Date(now.getTime() + 60_000);

      await h.tokens.insert({ tokenHash: "t-valid", userId: "c5", expiresAt: later });
      await h.tokens.insert({ tokenHash: "t-expired", userId: "c5", expiresAt: new Date(now.getTime() - 1) });

      expect(await h.tokens.consume("t-valid", now)).toEqual({ userId: "c5" });
      expect(await h.tokens.consume("t-valid", now)).toBeNull();
      expect(await h.tokens.consume("t-expired", now)).toBeNull();
      expect(await h.tokens.consume("t-unknown", now)).toBeNull();
    });

    it("invalidateForUser kills only that user's unused tokens", async () => {
      const h = await makeHarness();
      await h.seed({ id: "c6", email: "c6@example.test" });
      await h.seed({ id: "c7", email: "c7@example.test" });
      const now = new Date();
      const later = new Date(now.getTime() + 60_000);
      await h.tokens.insert({ tokenHash: "t-c6", userId: "c6", expiresAt: later });
      await h.tokens.insert({ tokenHash: "t-c7", userId: "c7", expiresAt: later });

      await h.tokens.invalidateForUser("c6", now);
      expect(await h.tokens.consume("t-c6", now)).toBeNull();
      expect(await h.tokens.consume("t-c7", now)).toEqual({ userId: "c7" });
    });

    it("lets exactly one of 25 concurrent requests consume the same token", async () => {
      const h = await makeHarness();
      await h.seed({ id: "c8", email: "c8@example.test" });
      const now = new Date();
      await h.tokens.insert({ tokenHash: "t-race", userId: "c8", expiresAt: new Date(now.getTime() + 60_000) });

      const results = await Promise.all(Array.from({ length: 25 }, () => h.tokens.consume("t-race", now)));
      expect(results.filter((r) => r !== null)).toHaveLength(1);
    });

    it("counts exactly `max` of 30 concurrent rate-limit requests as allowed", async () => {
      const h = await makeHarness();
      const limit = { max: 5, windowMs: 60_000 };
      const decisions = await Promise.all(Array.from({ length: 30 }, () => h.limiter.consume("race-key", limit)));
      expect(decisions.filter((d) => d.allowed)).toHaveLength(5);
      expect(decisions.filter((d) => !d.allowed).every((d) => d.retryAfterMs > 0)).toBe(true);
    });

    it("starts a new rate-limit window after the old one ends", async () => {
      const h = await makeHarness();
      const limit = { max: 1, windowMs: 150 };
      expect((await h.limiter.consume("window-key", limit)).allowed).toBe(true);
      expect((await h.limiter.consume("window-key", limit)).allowed).toBe(false);
      await new Promise((resolve) => setTimeout(resolve, 250));
      expect((await h.limiter.consume("window-key", limit)).allowed).toBe(true);
    });
  });
}

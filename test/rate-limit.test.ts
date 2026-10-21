import { describe, expect, it } from "vitest";
import { MemoryRateLimiter } from "../src/index.js";
import { fakeClock } from "./helpers.js";

const limit = { max: 3, windowMs: 60_000 };

describe("MemoryRateLimiter", () => {
  it("allows up to the limit, then blocks with a retry time", async () => {
    const clock = fakeClock();
    const limiter = new MemoryRateLimiter(clock.ms);
    const results = [];
    for (let i = 0; i < 4; i++) results.push(await limiter.consume("k", limit));

    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false]);
    expect(results.map((r) => r.remaining)).toEqual([2, 1, 0, 0]);
    expect(results[3]?.retryAfterMs).toBe(60_000);
  });

  it("starts a fresh window once the old one ends", async () => {
    const clock = fakeClock();
    const limiter = new MemoryRateLimiter(clock.ms);
    for (let i = 0; i < 4; i++) await limiter.consume("k", limit);
    clock.advance(60_001);
    expect((await limiter.consume("k", limit)).allowed).toBe(true);
  });

  it("counts each key separately", async () => {
    const limiter = new MemoryRateLimiter(fakeClock().ms);
    for (let i = 0; i < 4; i++) await limiter.consume("a", limit);
    expect((await limiter.consume("b", limit)).allowed).toBe(true);
  });

  it("keeps working across many keys and prune cycles", async () => {
    const clock = fakeClock();
    const limiter = new MemoryRateLimiter(clock.ms);
    for (let i = 0; i < 1200; i++) {
      await limiter.consume(`key-${i}`, limit);
      if (i % 300 === 0) clock.advance(61_000);
    }
    expect((await limiter.consume("key-1199", limit)).allowed).toBe(true);
  });
});

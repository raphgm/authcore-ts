import bcrypt from "bcryptjs";
import { describe, expect, it, vi } from "vitest";
import { checkPassword, ConfigError, PasswordHasher } from "../src/index.js";
import { testHasher } from "./helpers.js";

describe("PasswordHasher", () => {
  it("hashes without leaking the password and verifies the right one only", async () => {
    const hasher = testHasher();
    const hash = await hasher.hash("correct horse 9");
    expect(hash).not.toContain("correct horse");
    expect(await hasher.verify("correct horse 9", hash)).toBe(true);
    expect(await hasher.verify("wrong", hash)).toBe(false);
  });

  it("does not ignore everything after 72 bytes, unlike plain bcrypt", async () => {
    const shared = "a".repeat(72);
    const first = `${shared}-first`;
    const second = `${shared}-second`;

    // Plain bcrypt (what the original app used) treats these two different passwords as equal.
    const plain = await bcrypt.hash(first, 4);
    expect(await bcrypt.compare(second, plain)).toBe(true);

    const hasher = testHasher();
    const hash = await hasher.hash(first);
    expect(await hasher.verify(first, hash)).toBe(true);
    expect(await hasher.verify(second, hash)).toBe(false);
  });

  it("still verifies legacy plain-bcrypt hashes and flags them for upgrade", async () => {
    const hasher = testHasher();
    const legacy = await bcrypt.hash("old-password-1", 4);
    expect(await hasher.verify("old-password-1", legacy)).toBe(true);
    expect(await hasher.verify("nope", legacy)).toBe(false);
    expect(hasher.needsRehash(legacy)).toBe(true);
  });

  it("flags hashes made with a lower cost, but not current ones", async () => {
    const current = await testHasher().hash("password-123");
    expect(testHasher().needsRehash(current)).toBe(false);
    expect(new PasswordHasher({ cost: 5 }).needsRehash(current)).toBe(true);
  });

  it("verifyAbsent spends a real verification and always returns false", async () => {
    const hasher = testHasher();
    const compare = vi.spyOn(bcrypt, "compare");
    expect(await hasher.verifyAbsent("anything")).toBe(false);
    expect(compare).toHaveBeenCalledTimes(1);
    compare.mockRestore();
  });

  it("rejects unsafe bcrypt costs", () => {
    expect(() => new PasswordHasher({ cost: 3 })).toThrow(ConfigError);
    expect(() => new PasswordHasher({ cost: 32 })).toThrow(ConfigError);
    expect(() => new PasswordHasher({ cost: 10.5 })).toThrow(ConfigError);
  });
});

describe("checkPassword", () => {
  it("enforces the length policy", () => {
    expect(checkPassword("short")).toMatch(/at least 8/);
    expect(checkPassword("x".repeat(1025))).toMatch(/at most 1024/);
    expect(checkPassword("long enough")).toBeNull();
    expect(checkPassword("abc", { minLength: 3, maxLength: 5 })).toBeNull();
  });
});

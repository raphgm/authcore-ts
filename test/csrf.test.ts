import { describe, expect, it } from "vitest";
import { assertSameOrigin, AuthzError, isSameOrigin } from "../src/index.js";

const allowed = ["https://app.example.test"];
const post = (headers: Record<string, string>) =>
  new Request("https://app.example.test/api/auth/sign-in", { method: "POST", headers });

describe("isSameOrigin", () => {
  it("accepts a state-changing request from an allowed origin", () => {
    expect(isSameOrigin(post({ origin: "https://app.example.test" }), allowed)).toBe(true);
  });

  it("blocks a request from another origin", () => {
    expect(isSameOrigin(post({ origin: "https://evil.example" }), allowed)).toBe(false);
    expect(isSameOrigin(post({ origin: "https://app.example.test.evil.example" }), allowed)).toBe(false);
  });

  it("blocks a state-changing request that names no origin, and the opaque 'null' origin", () => {
    expect(isSameOrigin(post({}), allowed)).toBe(false);
    expect(isSameOrigin(post({ origin: "null" }), allowed)).toBe(false);
  });

  it("falls back to the Referer when Origin is absent", () => {
    expect(isSameOrigin(post({ referer: "https://app.example.test/login?x=1" }), allowed)).toBe(true);
    expect(isSameOrigin(post({ referer: "https://evil.example/login" }), allowed)).toBe(false);
  });

  it("lets safe methods through and ignores paths in the allowed list", () => {
    expect(isSameOrigin(new Request("https://app.example.test/x"), allowed)).toBe(true);
    expect(isSameOrigin(post({ origin: "https://app.example.test" }), ["https://app.example.test/some/path"])).toBe(true);
  });

  it("assertSameOrigin throws a 403", () => {
    expect(() => {
      assertSameOrigin(post({ origin: "https://evil.example" }), allowed);
    }).toThrow(AuthzError);
  });
});

import { describe, expect, it } from "vitest";
import { clearSessionCookie, readCookie, serializeSessionCookie } from "../src/index.js";

describe("session cookies", () => {
  it("is HttpOnly, SameSite=Lax and Secure by default", () => {
    const cookie = serializeSessionCookie("abc.def.ghi", { name: "sid", maxAgeSeconds: 60 });
    expect(cookie).toBe("sid=abc.def.ghi; Path=/; HttpOnly; SameSite=Lax; Max-Age=60; Secure");
  });

  it("drops Secure only when asked, for plain-http development", () => {
    const cookie = serializeSessionCookie("t", { maxAgeSeconds: 60, secure: false, sameSite: "Strict" });
    expect(cookie).toBe("session=t; Path=/; HttpOnly; SameSite=Strict; Max-Age=60");
  });

  it("refuses values that could inject extra cookie attributes", () => {
    expect(() => serializeSessionCookie("a; Domain=evil.test", { maxAgeSeconds: 1 })).toThrow(TypeError);
    expect(() => serializeSessionCookie("ok", { name: "bad name", maxAgeSeconds: 1 })).toThrow(TypeError);
  });

  it("clears the cookie by expiring it", () => {
    expect(clearSessionCookie({ name: "sid" })).toBe("sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure");
  });

  it("reads a named cookie from a Cookie header", () => {
    expect(readCookie("a=1; session=tok; b=2", "session")).toBe("tok");
    expect(readCookie("a=1", "session")).toBeUndefined();
    expect(readCookie(null, "session")).toBeUndefined();
    expect(readCookie("novalue; session=x", "session")).toBe("x");
  });
});

import { describe, expect, it } from "vitest";
import { AuthnError, AuthzError, ConfigError } from "../src/index.js";

describe("errors", () => {
  it("carry the HTTP status the caller should respond with", () => {
    expect(new AuthnError().status).toBe(401);
    expect(new AuthzError().status).toBe(403);
    expect(new AuthnError("Please sign in.").message).toBe("Please sign in.");
  });

  it("are identifiable with instanceof and by name", () => {
    expect(new AuthnError()).toBeInstanceOf(Error);
    expect(new AuthnError().name).toBe("AuthnError");
    expect(new AuthzError().name).toBe("AuthzError");
    expect(new ConfigError("bad").name).toBe("ConfigError");
  });
});

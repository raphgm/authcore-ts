import { describe, expect, it } from "vitest";
import { AuthzError, defineRbac } from "../src/index.js";

const rbac = defineRbac({
  ADMIN: ["asset:read", "asset:write", "user:manage"],
  TECHNICIAN: ["asset:read", "workorder:update"],
  AUDITOR: ["asset:read"],
} as const);

describe("defineRbac", () => {
  it("answers can() from the matrix", () => {
    expect(rbac.can("ADMIN", "user:manage")).toBe(true);
    expect(rbac.can("TECHNICIAN", "asset:write")).toBe(false);
    expect(rbac.can("AUDITOR", "asset:read")).toBe(true);
  });

  it("assertCan throws a 403 naming the missing permission", () => {
    expect(() => {
      rbac.assertCan("AUDITOR", "user:manage");
    }).toThrow(AuthzError);
    try {
      rbac.assertCan("AUDITOR", "user:manage");
    } catch (error) {
      expect((error as AuthzError).status).toBe(403);
      expect((error as AuthzError).message).toContain("user:manage");
    }
    expect(() => {
      rbac.assertCan("ADMIN", "user:manage");
    }).not.toThrow();
  });

  it("lists roles and permissions", () => {
    expect(rbac.roles).toEqual(["ADMIN", "TECHNICIAN", "AUDITOR"]);
    expect(rbac.permissionsOf("TECHNICIAN")).toEqual(["asset:read", "workorder:update"]);
  });

  it("denies an unknown role at runtime", () => {
    expect(rbac.can("GHOST" as never, "asset:read")).toBe(false);
    expect(rbac.permissionsOf("GHOST" as never)).toEqual([]);
  });

  it("rejects misspelled roles and permissions at compile time", () => {
    // @ts-expect-error "asset:wrte" is not a permission in the matrix
    rbac.can("ADMIN", "asset:wrte");
    // @ts-expect-error "ROOT" is not a role in the matrix
    rbac.can("ROOT", "asset:read");
  });
});

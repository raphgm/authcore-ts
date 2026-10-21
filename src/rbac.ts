import { AuthzError } from "./errors.js";

export interface Rbac<Role extends string, Permission extends string> {
  readonly roles: readonly Role[];
  can(role: Role, permission: Permission): boolean;
  /** Throws {@link AuthzError} when the role lacks the permission. */
  assertCan(role: Role, permission: Permission): void;
  permissionsOf(role: Role): readonly Permission[];
}

/**
 * Builds a typed role/permission checker from a plain matrix. Role and permission
 * names are inferred from the matrix, so `can("TECHNICIAN", "asset:wrte")` is a
 * compile-time error instead of a silent `false` at runtime.
 */
export function defineRbac<const Matrix extends Readonly<Record<string, readonly string[]>>>(
  matrix: Matrix,
): Rbac<Extract<keyof Matrix, string>, Matrix[keyof Matrix][number]> {
  type Role = Extract<keyof Matrix, string>;
  type Permission = Matrix[keyof Matrix][number];

  const sets = new Map<string, ReadonlySet<string>>(
    Object.entries(matrix).map(([role, permissions]) => [role, new Set(permissions)]),
  );

  const can = (role: Role, permission: Permission): boolean => sets.get(role)?.has(permission) ?? false;

  return {
    roles: Object.keys(matrix) as Role[],
    can,
    assertCan(role, permission) {
      if (!can(role, permission)) throw new AuthzError(`Missing permission: ${permission}`);
    },
    permissionsOf: (role) => matrix[role] ?? [],
  };
}

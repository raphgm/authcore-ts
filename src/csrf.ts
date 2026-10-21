import { AuthzError } from "./errors.js";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function originOf(value: string | null): string | null {
  if (!value) return null;
  try {
    const { origin } = new URL(value);
    return origin === "null" ? null : origin;
  } catch {
    return null;
  }
}

/**
 * Cookie sessions need protection against cross-site form posts. For any method that
 * can change state, the request must name its origin (the Origin header, or the
 * Referer when a browser omits Origin) and that origin must be one you allow.
 * A state-changing request with no origin at all is rejected.
 */
export function isSameOrigin(request: Request, allowedOrigins: readonly string[]): boolean {
  if (SAFE_METHODS.has(request.method.toUpperCase())) return true;
  const claimed = originOf(request.headers.get("origin")) ?? originOf(request.headers.get("referer"));
  if (!claimed) return false;
  return allowedOrigins.some((allowed) => originOf(allowed) === claimed);
}

export function assertSameOrigin(request: Request, allowedOrigins: readonly string[]): void {
  if (!isSameOrigin(request, allowedOrigins)) throw new AuthzError("Cross-origin request blocked.");
}

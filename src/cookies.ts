export interface SessionCookieOptions {
  /** Cookie name. Defaults to "session". */
  name?: string;
  maxAgeSeconds: number;
  /** Set false only for plain-http local development. */
  secure?: boolean;
  sameSite?: "Lax" | "Strict";
}

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

function cookieName(name: string | undefined): string {
  const value = name ?? "session";
  if (!TOKEN.test(value)) throw new TypeError(`Invalid cookie name: ${value}`);
  return value;
}

/** Builds a `Set-Cookie` header value: HttpOnly, Path=/, SameSite=Lax and Secure by default. */
export function serializeSessionCookie(token: string, options: SessionCookieOptions): string {
  if (!TOKEN.test(token)) throw new TypeError("Session token contains characters that are not allowed in a cookie.");
  return [
    `${cookieName(options.name)}=${token}`,
    "Path=/",
    "HttpOnly",
    `SameSite=${options.sameSite ?? "Lax"}`,
    `Max-Age=${options.maxAgeSeconds}`,
    ...(options.secure === false ? [] : ["Secure"]),
  ].join("; ");
}

export function clearSessionCookie(options: Omit<SessionCookieOptions, "maxAgeSeconds">): string {
  return [
    `${cookieName(options.name)}=`,
    "Path=/",
    "HttpOnly",
    `SameSite=${options.sameSite ?? "Lax"}`,
    "Max-Age=0",
    ...(options.secure === false ? [] : ["Secure"]),
  ].join("; ");
}

/** Reads one cookie from a `Cookie` request header. */
export function readCookie(header: string | null | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return undefined;
}

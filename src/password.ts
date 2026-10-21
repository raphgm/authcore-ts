import { createHash } from "node:crypto";
import bcrypt from "bcryptjs";
import { ConfigError } from "./errors.js";

/**
 * bcrypt only reads the first 72 bytes of its input, so two long passwords that
 * share a 72-byte prefix would hash identically. New hashes therefore bcrypt the
 * base64 of the password's SHA-256 digest (always 44 characters) and carry this
 * prefix, the same approach Django uses for `bcrypt_sha256`. Hashes without the
 * prefix are treated as plain bcrypt, so existing databases keep working and are
 * upgraded the next time each user signs in.
 */
const PREFIX = "$bcrypt-sha256$v1$";

export interface PasswordPolicy {
  readonly minLength: number;
  readonly maxLength: number;
}

export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = { minLength: 8, maxLength: 1024 };

/** Returns a user-facing message if the password is unacceptable, otherwise null. */
export function checkPassword(password: string, policy: PasswordPolicy = DEFAULT_PASSWORD_POLICY): string | null {
  if (password.length < policy.minLength) return `Password must be at least ${policy.minLength} characters.`;
  if (password.length > policy.maxLength) return `Password must be at most ${policy.maxLength} characters.`;
  return null;
}

const prehash = (password: string): string => createHash("sha256").update(password, "utf8").digest("base64");

export class PasswordHasher {
  readonly cost: number;
  #dummyHash: Promise<string> | undefined;

  constructor(options: { cost?: number } = {}) {
    const cost = options.cost ?? 12;
    if (!Number.isInteger(cost) || cost < 4 || cost > 31) {
      throw new ConfigError("bcrypt cost must be an integer between 4 and 31.");
    }
    this.cost = cost;
  }

  async hash(password: string): Promise<string> {
    return PREFIX + (await bcrypt.hash(prehash(password), this.cost));
  }

  async verify(password: string, stored: string): Promise<boolean> {
    if (stored.startsWith(PREFIX)) return bcrypt.compare(prehash(password), stored.slice(PREFIX.length));
    return bcrypt.compare(password, stored);
  }

  /** True for legacy plain-bcrypt hashes and for hashes made with a lower cost than configured. */
  needsRehash(stored: string): boolean {
    if (!stored.startsWith(PREFIX)) return true;
    const match = /^\$2[abxy]\$(\d{2})\$/.exec(stored.slice(PREFIX.length));
    return !match || Number(match[1]) < this.cost;
  }

  /**
   * Spends the same CPU as a real verification. Call it when no user matched, so
   * response time does not reveal which email addresses have accounts.
   */
  async verifyAbsent(password: string): Promise<false> {
    const dummy = await (this.#dummyHash ??= this.hash("authcore-ts dummy password"));
    await this.verify(password, dummy);
    return false;
  }
}

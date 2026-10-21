/** Thrown when a caller is not authenticated. Maps to HTTP 401. */
export class AuthnError extends Error {
  readonly status = 401 as const;
  constructor(message = "Authentication required.") {
    super(message);
    this.name = "AuthnError";
  }
}

/** Thrown when an authenticated caller lacks permission. Maps to HTTP 403. */
export class AuthzError extends Error {
  readonly status = 403 as const;
  constructor(message = "You do not have access to this resource.") {
    super(message);
    this.name = "AuthzError";
  }
}

/** Thrown at construction time for unsafe or invalid configuration, so mistakes fail fast. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

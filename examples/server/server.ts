// A small HTTP server that wires authcore-ts to Postgres (or to memory when DATABASE_URL
// is unset). It exists to show the library working end to end, not as a framework.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
  AuthnError,
  AuthService,
  AuthzError,
  MemoryRateLimiter,
  MemoryResetTokenStore,
  MemoryUserStore,
  PasswordHasher,
  POSTGRES_SCHEMA_SQL,
  PostgresRateLimiter,
  PostgresResetTokenStore,
  PostgresUserStore,
  ResetTokenService,
  SessionService,
  assertSameOrigin,
  clearSessionCookie,
  defineRbac,
  readCookie,
  serializeSessionCookie,
  type PostgresUser,
  type Queryable,
  type RateLimiter,
  type ResetTokenStore,
  type UserStore,
} from "authcore-ts";

const rbac = defineRbac({
  ADMIN: ["report:read", "user:manage"],
  VIEWER: ["report:read"],
} as const);

const env = (name: string): string | undefined => process.env[name] || undefined;
const required = (name: string): string => {
  const value = env(name);
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const COOKIE = "session";
const secure = env("COOKIE_SECURE") !== "false";
const allowedOrigins = (env("ALLOWED_ORIGINS") ?? "http://localhost:3000").split(",").map((o) => o.trim());
const trustProxy = env("TRUST_PROXY") === "1";

// --- storage -----------------------------------------------------------------------
let users: UserStore<PostgresUser>;
let tokens: ResetTokenStore;
let limiter: RateLimiter;
let ping: () => Promise<void> = () => Promise.resolve();
const hasher = new PasswordHasher({ cost: Number(env("BCRYPT_COST") ?? 12) });

// Optional demo accounts, e.g. SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD and SEED_VIEWER_EMAIL / SEED_VIEWER_PASSWORD.
async function seedUsers(
  find: (email: string) => Promise<unknown>,
  create: (u: { id: string; email: string; passwordHash: string; role: string }) => Promise<void>,
) {
  for (const role of ["ADMIN", "VIEWER"] as const) {
    const email = env(`SEED_${role}_EMAIL`)?.toLowerCase();
    const password = env(`SEED_${role}_PASSWORD`);
    if (email && password && !(await find(email))) {
      await create({ id: `seed-${role.toLowerCase()}`, email, passwordHash: await hasher.hash(password), role });
    }
  }
}

const databaseUrl = env("DATABASE_URL");
if (databaseUrl) {
  const { default: pg } = await import("pg");
  const pool: Queryable & { end(): Promise<void> } = new pg.Pool({ connectionString: databaseUrl, max: 10 });
  if (env("AUTO_MIGRATE") === "1") await pool.query(POSTGRES_SCHEMA_SQL);
  const store = new PostgresUserStore(pool);
  users = store;
  tokens = new PostgresResetTokenStore(pool);
  limiter = new PostgresRateLimiter(pool);
  ping = async () => {
    await pool.query("select 1");
  };
  await seedUsers((email) => store.findByEmail(email), (u) => store.create(u));
} else {
  const memory = new MemoryUserStore<PostgresUser>();
  users = memory;
  tokens = new MemoryResetTokenStore();
  limiter = new MemoryRateLimiter();
  await seedUsers(
    (email) => memory.findByEmail(email),
    (u) => {
      memory.add({ ...u, active: true, sessionVersion: 0 });
      return Promise.resolve();
    },
  );
}

const sessions = new SessionService<PostgresUser>({ secret: required("SESSION_SECRET"), findUserById: (id) => users.findById(id) });
const auth = new AuthService<PostgresUser>({
  users,
  hasher,
  sessions,
  resetTokens: new ResetTokenService(tokens),
  rateLimiter: limiter,
  audit: (event) => {
    console.log(JSON.stringify({ level: "info", msg: "auth", ...event }));
  },
});

// --- http helpers ------------------------------------------------------------------
const send = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string | string[]> = {}): void => {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
  res.end(JSON.stringify(body));
};

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 10_000) throw new HttpError(413, "Request body too large.");
    chunks.push(chunk as Buffer);
  }
  try {
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
  } catch {
    /* fall through */
  }
  throw new HttpError(400, "Request body must be a JSON object.");
}

const text = (value: unknown, field: string): string => {
  if (typeof value !== "string") throw new HttpError(400, `${field} must be a string.`);
  return value;
};

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

const toWebRequest = (req: IncomingMessage): Request => {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) if (typeof value === "string") headers.set(name, value);
  return new Request(`http://${req.headers.host ?? "localhost"}${req.url ?? "/"}`, { method: req.method ?? "GET", headers });
};

const clientIp = (req: IncomingMessage): string => {
  const forwarded = req.headers["x-forwarded-for"];
  if (trustProxy && typeof forwarded === "string") return forwarded.split(",")[0]?.trim() ?? "unknown";
  return req.socket.remoteAddress ?? "unknown";
};

async function currentUser(req: IncomingMessage): Promise<PostgresUser> {
  const user = await sessions.verify(readCookie(req.headers.cookie, COOKIE));
  if (!user) throw new AuthnError();
  return user;
}

const publicUser = (u: PostgresUser) => ({ id: u.id, email: u.email, role: u.role });
const cookieOptions = { name: COOKIE, secure };

// --- routes ------------------------------------------------------------------------
async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const { pathname } = new URL(req.url ?? "/", "http://localhost");
  const method = req.method ?? "GET";
  const key = `${method} ${pathname}`;

  if (key === "GET /healthz") {
    await ping();
    send(res, 200, { status: "ok" });
    return;
  }

  if (method === "POST") assertSameOrigin(toWebRequest(req), allowedOrigins);

  switch (key) {
    case "POST /auth/sign-in": {
      const body = await readJson(req);
      const result = await auth.signIn({ email: text(body["email"], "email"), password: text(body["password"], "password"), ip: clientIp(req) });
      if (result.ok) {
        const cookie = serializeSessionCookie(result.token, { ...cookieOptions, maxAgeSeconds: sessions.maxAgeSeconds });
        send(res, 200, { user: publicUser(result.user) }, { "set-cookie": cookie });
        return;
      }
      if (result.reason === "rate_limited") {
        send(res, 429, { error: "Too many attempts. Try again shortly." }, { "retry-after": String(Math.ceil(result.retryAfterMs / 1000)) });
        return;
      }
      send(res, 401, { error: "Invalid email or password." });
      return;
    }

    case "POST /auth/sign-out":
      send(res, 200, { ok: true }, { "set-cookie": clearSessionCookie(cookieOptions) });
      return;

    case "GET /me":
      send(res, 200, { user: publicUser(await currentUser(req)) });
      return;

    case "GET /admin/reports": {
      const user = await currentUser(req);
      rbac.assertCan(user.role as "ADMIN" | "VIEWER", "report:read");
      send(res, 200, { reports: [], viewedBy: user.email });
      return;
    }

    case "GET /admin/users": {
      const user = await currentUser(req);
      rbac.assertCan(user.role as "ADMIN" | "VIEWER", "user:manage");
      send(res, 200, { ok: true });
      return;
    }

    case "POST /auth/forgot": {
      const body = await readJson(req);
      const issued = await auth.requestPasswordReset(text(body["email"], "email"));
      // A real app emails this link. Printing it is only for trying the example locally.
      if (issued && env("LOG_RESET_LINKS") === "1") console.log(`reset link for ${issued.user.email}: /reset/${issued.token}`);
      // Identical response whether or not the email exists.
      send(res, 202, { ok: true });
      return;
    }

    case "POST /auth/reset": {
      const body = await readJson(req);
      const result = await auth.resetPassword(text(body["token"], "token"), text(body["password"], "password"));
      if (result.ok) {
        send(res, 200, { ok: true });
        return;
      }
      if (result.reason === "weak_password") {
        send(res, 400, { error: result.message });
        return;
      }
      send(res, 400, { error: "This reset link is invalid or has expired." });
      return;
    }

    default:
      send(res, 404, { error: "Not found." });
      return;
  }
}

const server = createServer((req, res) => {
  route(req, res).catch((error: unknown) => {
    if (error instanceof HttpError) {
      send(res, error.status, { error: error.message });
      return;
    }
    if (error instanceof AuthnError) {
      send(res, 401, { error: error.message });
      return;
    }
    if (error instanceof AuthzError) {
      send(res, 403, { error: error.message });
      return;
    }
    console.error(JSON.stringify({ level: "error", msg: "unhandled", error: error instanceof Error ? error.message : String(error) }));
    send(res, 500, { error: "Internal error." });
    return;
  });
});

const port = Number(env("PORT") ?? 3000);
server.listen(port, () => {
  console.log(JSON.stringify({ level: "info", msg: "listening", port, store: databaseUrl ? "postgres" : "memory" }));
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}

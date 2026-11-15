import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE = "astra_dashboard_session";
export const CSRF_COOKIE = "astra_dashboard_csrf";

export type DashboardAuthConfig = {
  apiUrl: string;
  dashboardOrigin: string;
  apiToken: string;
  loginToken: string;
  sessionSecret: string;
  sessionTtlSeconds: number;
  secureCookies: boolean;
};

export type DashboardSession = {
  sessionId: string;
  csrfToken: string;
  expiresAt: number;
};

type SignedSession = Pick<DashboardSession, "sessionId" | "expiresAt">;

function parsePositiveInteger(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export function loadDashboardAuthConfig(
  environment: NodeJS.ProcessEnv = process.env,
): DashboardAuthConfig {
  const apiUrl = environment.ASTRA_API_URL?.trim() || "http://127.0.0.1:8000";
  const dashboardOrigin = environment.ASTRA_DASHBOARD_ORIGIN?.trim() || "";
  const apiToken = environment.ASTRA_DASHBOARD_API_TOKEN?.trim() || "";
  const loginToken = environment.ASTRA_DASHBOARD_LOGIN_TOKEN?.trim() || "";
  const sessionSecret = environment.ASTRA_DASHBOARD_SESSION_SECRET?.trim() || "";
  const secureCookies = environment.NODE_ENV === "production"
    ? true
    : environment.ASTRA_DASHBOARD_COOKIE_SECURE === "true";

  return {
    apiUrl: validateApiUrl(apiUrl),
    dashboardOrigin: dashboardOrigin ? validateOrigin(dashboardOrigin) : "",
    apiToken,
    loginToken,
    sessionSecret,
    sessionTtlSeconds: parsePositiveInteger(
      environment.ASTRA_DASHBOARD_SESSION_TTL_SECONDS,
      3_600,
    ),
    secureCookies,
  };
}

function validateApiUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("ASTRA_API_URL must be an http(s) URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("ASTRA_API_URL must be an http(s) URL");
  }
  return parsed.toString().replace(/\/$/, "");
}

function validateOrigin(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("ASTRA_DASHBOARD_ORIGIN must be an http(s) origin");
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.pathname !== "/"
    || parsed.search || parsed.hash || parsed.username || parsed.password) {
    throw new Error("ASTRA_DASHBOARD_ORIGIN must be an http(s) origin");
  }
  return parsed.origin;
}

export function requireDashboardAuthConfig(
  environment: NodeJS.ProcessEnv = process.env,
): DashboardAuthConfig {
  const config = loadDashboardAuthConfig(environment);
  if (!config.dashboardOrigin || !config.apiToken || !config.loginToken || !config.sessionSecret) {
    throw new Error(
      "Dashboard local authentication is not configured; set server-side ASTRA_DASHBOARD_ORIGIN, "
        + "ASTRA_DASHBOARD_API_TOKEN, ASTRA_DASHBOARD_LOGIN_TOKEN, and ASTRA_DASHBOARD_SESSION_SECRET.",
    );
  }
  if (config.sessionSecret.length < 32) {
    throw new Error("ASTRA_DASHBOARD_SESSION_SECRET must be at least 32 characters");
  }
  return config;
}

function safeEqual(left: string, right: string): boolean {
  const leftHash = createHmac("sha256", "astra-dashboard-compare").update(left).digest();
  const rightHash = createHmac("sha256", "astra-dashboard-compare").update(right).digest();
  return timingSafeEqual(leftHash, rightHash);
}

function signPayload(payload: string, secret: string): string {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

function encodeSession(session: SignedSession, secret: string): string {
  const payload = Buffer.from(JSON.stringify(session), "utf8").toString("base64url");
  return `${payload}.${signPayload(payload, secret)}`;
}

function decodeSession(value: string, secret: string): SignedSession | null {
  const [payload, signature] = value.split(".");
  if (!payload || !signature || !safeEqual(signature, signPayload(payload, secret))) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Partial<SignedSession>;
    if (
      typeof parsed.sessionId !== "string"
      || !parsed.sessionId
      || typeof parsed.expiresAt !== "number"
      || !Number.isSafeInteger(parsed.expiresAt)
    ) {
      return null;
    }
    return { sessionId: parsed.sessionId, expiresAt: parsed.expiresAt };
  } catch {
    return null;
  }
}

function readCookie(request: Request, name: string): string | null {
  const cookieHeader = request.headers.get("cookie") ?? "";
  for (const value of cookieHeader.split(";")) {
    const separator = value.indexOf("=");
    if (separator < 0) continue;
    const key = value.slice(0, separator).trim();
    if (key === name) {
      try {
        return decodeURIComponent(value.slice(separator + 1).trim());
      } catch {
        return null;
      }
    }
  }
  return null;
}

function cookieValue(value: string): string {
  return encodeURIComponent(value);
}

export function serializeCookie(
  name: string,
  value: string,
  options: {
    httpOnly: boolean;
    secure: boolean;
    sameSite: "Lax" | "Strict";
    maxAge: number;
  },
): string {
  return [
    `${name}=${cookieValue(value)}`,
    "Path=/",
    `Max-Age=${options.maxAge}`,
    `SameSite=${options.sameSite}`,
    ...(options.httpOnly ? ["HttpOnly"] : []),
    ...(options.secure ? ["Secure"] : []),
  ].join("; ");
}

export function clearCookie(name: string, secure: boolean): string {
  return serializeCookie(name, "", {
    httpOnly: name === SESSION_COOKIE,
    secure,
    sameSite: "Lax",
    maxAge: 0,
  });
}

export class DashboardSessionStore {
  private readonly sessions = new Map<string, DashboardSession>();

  constructor(private readonly config: DashboardAuthConfig) {}

  authenticate(loginToken: string): DashboardSession | null {
    if (!safeEqual(loginToken, this.config.loginToken)) return null;
    const now = Math.floor(Date.now() / 1_000);
    const session: DashboardSession = {
      sessionId: randomBytes(32).toString("base64url"),
      csrfToken: randomBytes(32).toString("base64url"),
      expiresAt: now + this.config.sessionTtlSeconds,
    };
    this.sessions.set(session.sessionId, session);
    return session;
  }

  cookieFor(session: DashboardSession): string {
    return encodeSession(
      { sessionId: session.sessionId, expiresAt: session.expiresAt },
      this.config.sessionSecret,
    );
  }

  sessionFrom(request: Request): DashboardSession | null {
    const cookie = readCookie(request, SESSION_COOKIE);
    if (!cookie) return null;
    const signed = decodeSession(cookie, this.config.sessionSecret);
    if (!signed) return null;
    const session = this.sessions.get(signed.sessionId);
    const now = Math.floor(Date.now() / 1_000);
    if (!session || session.expiresAt !== signed.expiresAt || session.expiresAt <= now) {
      this.sessions.delete(signed.sessionId);
      return null;
    }
    return session;
  }

  revoke(request: Request): void {
    const session = this.sessionFrom(request);
    if (session) this.sessions.delete(session.sessionId);
  }

  csrfMatches(request: Request, session: DashboardSession): boolean {
    const cookieToken = readCookie(request, CSRF_COOKIE);
    const headerToken = request.headers.get("x-astra-csrf");
    return Boolean(cookieToken && headerToken)
      && safeEqual(cookieToken ?? "", session.csrfToken)
      && safeEqual(headerToken ?? "", session.csrfToken);
  }
}

let sharedSessionStore: DashboardSessionStore | undefined;
let sharedSessionStoreKey = "";

export function getDashboardSessionStore(
  config: DashboardAuthConfig = requireDashboardAuthConfig(),
): DashboardSessionStore {
  const key = `${config.sessionSecret}\u0000${config.loginToken}`;
  if (!sharedSessionStore || sharedSessionStoreKey !== key) {
    sharedSessionStore = new DashboardSessionStore(config);
    sharedSessionStoreKey = key;
  }
  return sharedSessionStore;
}

export function sameOrigin(request: Request, expectedOrigin?: string): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    if (expectedOrigin) return new URL(origin).origin === expectedOrigin;
    const requestUrl = new URL(request.url);
    const host = request.headers.get("host");
    if (host) requestUrl.host = host;
    return new URL(origin).origin === requestUrl.origin;
  } catch {
    return false;
  }
}

export function dashboardCookieHeaders(
  config: DashboardAuthConfig,
  store: DashboardSessionStore,
  session: DashboardSession,
): string[] {
  return [
    serializeCookie(SESSION_COOKIE, store.cookieFor(session), {
      httpOnly: true,
      secure: config.secureCookies,
      sameSite: "Lax",
      maxAge: config.sessionTtlSeconds,
    }),
    serializeCookie(CSRF_COOKIE, session.csrfToken, {
      httpOnly: false,
      secure: config.secureCookies,
      sameSite: "Lax",
      maxAge: config.sessionTtlSeconds,
    }),
  ];
}

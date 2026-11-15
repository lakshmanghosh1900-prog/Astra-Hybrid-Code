import { describe, expect, it } from "vitest";
import {
  CSRF_COOKIE,
  DashboardSessionStore,
  SESSION_COOKIE,
  requireDashboardAuthConfig,
  sameOrigin,
  serializeCookie,
} from "../lib/server/auth";

const config = {
  apiUrl: "http://api:8000",
  dashboardOrigin: "https://dashboard.test",
  apiToken: "server-api-token",
  loginToken: "server-login-token",
  sessionSecret: "a".repeat(32),
  sessionTtlSeconds: 3_600,
  secureCookies: true,
};

describe("dashboard server authentication", () => {
  it("round-trips an expiring signed session and validates CSRF", () => {
    const store = new DashboardSessionStore(config);
    const session = store.authenticate(config.loginToken);
    expect(session).not.toBeNull();
    if (!session) return;

    const request = new Request("https://dashboard.test/api/proxy/tasks", {
      headers: {
        cookie: [
          serializeCookie(SESSION_COOKIE, store.cookieFor(session), { httpOnly: true, secure: true, sameSite: "Lax", maxAge: 3_600 }),
          serializeCookie(CSRF_COOKIE, session.csrfToken, { httpOnly: false, secure: true, sameSite: "Lax", maxAge: 3_600 }),
        ].join("; "),
        origin: "https://dashboard.test",
        "x-astra-csrf": session.csrfToken,
      },
    });
    expect(store.sessionFrom(request)?.sessionId).toBe(session.sessionId);
    expect(store.csrfMatches(request, session)).toBe(true);
    expect(sameOrigin(request)).toBe(true);
  });

  it("rejects short session secrets and cross-origin mutations", () => {
    expect(() => requireDashboardAuthConfig({
      NODE_ENV: "test",
      ASTRA_API_URL: "http://api:8000",
      ASTRA_DASHBOARD_ORIGIN: "https://dashboard.test",
      ASTRA_DASHBOARD_API_TOKEN: "api-token",
      ASTRA_DASHBOARD_LOGIN_TOKEN: "login-token",
      ASTRA_DASHBOARD_SESSION_SECRET: "too-short",
    })).toThrow(/at least 32/);
    expect(sameOrigin(new Request("https://dashboard.test/api/auth/logout", {
      method: "POST",
      headers: { origin: "https://evil.test" },
    }), "https://dashboard.test")).toBe(false);
  });

  it("fails closed on malformed cookie encoding", () => {
    const store = new DashboardSessionStore(config);
    const request = new Request("https://dashboard.test/api/proxy/tasks", {
      headers: { cookie: `${SESSION_COOKIE}=%invalid` },
    });
    expect(store.sessionFrom(request)).toBeNull();
  });
});

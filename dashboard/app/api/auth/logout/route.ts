import {
  CSRF_COOKIE,
  SESSION_COOKIE,
  clearCookie,
  getDashboardSessionStore,
  requireDashboardAuthConfig,
  sameOrigin,
} from "../../../../lib/server/auth";

export async function POST(request: Request): Promise<Response> {
  try {
    const config = requireDashboardAuthConfig();
    if (!sameOrigin(request, config.dashboardOrigin)) {
      return Response.json({ detail: "same-origin request required" }, { status: 403 });
    }
    const store = getDashboardSessionStore(config);
    const session = store.sessionFrom(request);
    if (session && !store.csrfMatches(request, session)) {
      return Response.json({ detail: "CSRF validation failed" }, { status: 403 });
    }
    if (session) store.revoke(request);
    const headers = new Headers({ "Cache-Control": "no-store" });
    headers.append("Set-Cookie", clearCookie(SESSION_COOKIE, config.secureCookies));
    headers.append("Set-Cookie", clearCookie(CSRF_COOKIE, config.secureCookies));
    return new Response(null, { status: 204, headers });
  } catch {
    return Response.json(
      { detail: "dashboard authentication is unavailable" },
      { status: 503 },
    );
  }
}

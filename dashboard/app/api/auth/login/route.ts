import {
  dashboardCookieHeaders,
  getDashboardSessionStore,
  requireDashboardAuthConfig,
  sameOrigin,
} from "../../../../lib/server/auth";

function jsonResponse(body: unknown, status: number, cookies: string[] = []): Response {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
  });
  for (const cookie of cookies) headers.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(body), { status, headers });
}

export async function POST(request: Request): Promise<Response> {
  let loginToken: unknown;
  try {
    const body = await request.json() as { loginToken?: unknown };
    loginToken = body.loginToken;
  } catch {
    return jsonResponse({ detail: "invalid login request" }, 400);
  }
  if (typeof loginToken !== "string" || !loginToken) {
    return jsonResponse({ detail: "login token is required" }, 400);
  }

  try {
    const config = requireDashboardAuthConfig();
    if (!sameOrigin(request, config.dashboardOrigin)) {
      return jsonResponse({ detail: "same-origin request required" }, 403);
    }
    const store = getDashboardSessionStore(config);
    const session = store.authenticate(loginToken);
    if (!session) return jsonResponse({ detail: "invalid login credentials" }, 401);
    return jsonResponse(
      { authenticated: true, expiresAt: session.expiresAt },
      200,
      dashboardCookieHeaders(config, store, session),
    );
  } catch {
    return jsonResponse({ detail: "dashboard authentication is unavailable" }, 503);
  }
}

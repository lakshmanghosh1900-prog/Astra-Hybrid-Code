import { getDashboardSessionStore, requireDashboardAuthConfig } from "../../../../lib/server/auth";

export async function GET(request: Request): Promise<Response> {
  try {
    const config = requireDashboardAuthConfig();
    const session = getDashboardSessionStore(config).sessionFrom(request);
    if (!session) {
      return Response.json(
        { authenticated: false },
        { status: 401, headers: { "Cache-Control": "no-store" } },
      );
    }
    return Response.json(
      { authenticated: true, expiresAt: session.expiresAt },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch {
    return Response.json(
      { detail: "dashboard authentication is unavailable" },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }
}

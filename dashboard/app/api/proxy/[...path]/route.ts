import {
  getDashboardSessionStore,
  requireDashboardAuthConfig,
  sameOrigin,
} from "../../../../lib/server/auth";

type RouteContext = { params: Promise<{ path?: string[] }> };

function jsonResponse(body: unknown, status: number): Response {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

async function proxy(request: Request, context: RouteContext, method: "GET" | "POST") {
  let config;
  let store;
  try {
    config = requireDashboardAuthConfig();
    store = getDashboardSessionStore(config);
  } catch {
    return jsonResponse({ detail: "dashboard authentication is unavailable" }, 503);
  }

  const session = store.sessionFrom(request);
  if (!session) return jsonResponse({ detail: "authentication required" }, 401);
  if (method === "POST") {
    if (!sameOrigin(request, config.dashboardOrigin)) {
      return jsonResponse({ detail: "same-origin request required" }, 403);
    }
    if (!store.csrfMatches(request, session)) {
      return jsonResponse({ detail: "CSRF validation failed" }, 403);
    }
  }

  const segments = (await context.params).path ?? [];
  if (!segments.length || segments.some((segment) => !segment || segment === "." || segment === "..")) {
    return jsonResponse({ detail: "invalid API path" }, 400);
  }
  const upstreamUrl = `${config.apiUrl}/${segments.map(encodeURIComponent).join("/")}${new URL(request.url).search}`;
  const headers = new Headers({ Authorization: `Bearer ${config.apiToken}` });
  for (const name of ["accept", "content-type"]) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }

  try {
    const upstream = await fetch(upstreamUrl, {
      method,
      headers,
      body: method === "POST" ? await request.arrayBuffer() : undefined,
      cache: "no-store",
    });
    const responseHeaders = new Headers({ "Cache-Control": "no-store" });
    const contentType = upstream.headers.get("content-type");
    if (contentType) responseHeaders.set("content-type", contentType);
    return new Response(upstream.body, {
      status: upstream.status,
      headers: responseHeaders,
    });
  } catch {
    return jsonResponse({ detail: "Astra API is unavailable" }, 502);
  }
}

export function GET(request: Request, context: RouteContext) {
  return proxy(request, context, "GET");
}

export function POST(request: Request, context: RouteContext) {
  return proxy(request, context, "POST");
}

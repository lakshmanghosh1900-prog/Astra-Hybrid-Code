# Astra Coder Dashboard

Next.js 15 + Tailwind dashboard for the Astra Coder FastAPI control plane. It
uses a small Next server runtime for login, session cookies, CSRF checks, and a
same-origin API proxy; policy, task state, approvals, and evidence remain
authoritative in the Python API.

## Run

```bash
npm ci
export ASTRA_DASHBOARD_ORIGIN=http://127.0.0.1:3000
export ASTRA_DASHBOARD_API_TOKEN='<server-side-api-token>'
export ASTRA_DASHBOARD_LOGIN_TOKEN='<dashboard-login-token>'
export ASTRA_DASHBOARD_SESSION_SECRET='<at-least-32-character-secret>'
npm run dev
```

Set the server-only `ASTRA_API_URL` when the API is not at
`http://127.0.0.1:8000`. The browser calls only same-origin `/api/proxy/*`
routes.

## Authentication

The dashboard login accepts a server-configured
`ASTRA_DASHBOARD_LOGIN_TOKEN`, creates an expiring signed `HttpOnly` session
cookie plus a readable CSRF cookie, and provides logout. All mutating browser
requests require the configured `ASTRA_DASHBOARD_ORIGIN`, same-origin `Origin`,
and CSRF checks. The Next server sends the
server-only `ASTRA_DASHBOARD_API_TOKEN` to the FastAPI API; no API bearer token
is compiled into browser code or Docker build arguments.

## Checks

```bash
npm test
npm run lint
npm run build
```

The production build uses Next `output: "standalone"` and runs its generated
`server.js` in the container so the server-side session and proxy routes are
available. The dashboard must not be served as static files. `npm audit --omit=dev
--audit-level=high` is the release check for its server runtime.

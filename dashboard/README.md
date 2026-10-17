# Astra Coder Dashboard

Next.js 14 + Tailwind client for the Astra Coder FastAPI control plane. It is intentionally a client-only dashboard: policy, task state, approvals, and evidence remain authoritative in the Python API.

## Run

```bash
npm ci
npm run dev
```

Set `NEXT_PUBLIC_ASTRA_API_URL` when the API is not at `http://127.0.0.1:8000`.

## Checks

```bash
npm test
npm run lint
npm run build
```

The production build uses Next `output: "export"` and should be served as static files. This avoids deploying the Next server runtime. The locked Next.js 14 dependency still appears in current `npm audit` advisories whose fixes require a later major version; this is recorded as a release limitation and must be re-evaluated before public deployment.

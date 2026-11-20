# 07-A and 14-A live verification

Date: 2026-11-21 (dashboard run started 02:31:55 +05:30).
Base: `23fee82`. Branch: `feat/07a-14a-live-verification`.

## 14-A Dashboard: PASS at the requested threshold

Node v24.18.0, npm 11.16.0. Ran from a disposable archive of the committed dashboard with its lockfile.

| Command | Exit | Evidence |
| --- | ---: | --- |
| `npm ci` | 0 | Installed 491 packages; npm reported deprecation and install-script policy warnings. |
| `npm test` | 0 | Vitest 4.1.12: all 7 tests passed across 3 files. |
| `npm run lint` | 0 | No ESLint warnings or errors; Next.js warned that next lint is deprecated. |
| `npm run build` | 0 | Next.js 15.5.28 compiled, passed type and lint checks, and generated 7/7 static pages. |
| `npm audit --omit=dev --audit-level=high` | 0 | No production findings at high or critical severity. npm reported one affected Next.js dependency at moderate severity, citing GHSA-7qx7-33qx-rqx2, GHSA-f3mh-rxg3-f5g2, and GHSA-pc58-hwjq-p385. npm proposed 15.5.29 outside the pinned version; no remediation was run. |

Audit verdict applies to production dependencies at the high threshold; it does not imply zero advisories.

## 07-A Secure Sandbox: PASS for the live fixture

Docker client and engine 29.9.3, API 1.56; Docker Desktop 4.99.0, context desktop-linux, server linux/amd64. Version and image inventory exited 0.

Image assumption: reused the existing ASTRA-owned `astracoder-api:local` image, ID `sha256:6ac42c38f87579ab7647bdf29eb606f51bec6725062ca0b96e6b99283deb9906`. Its local metadata identifies the ASTRA API service; its build commit was not independently established. The host sandbox and adapter were imported from the pinned checkout. No build or pull was needed.

| Probe | Observed result |
| --- | --- |
| DockerSandbox.run, benign argv | Exit 0; arguments containing a space and a literal semicolon arrived unchanged. |
| Isolation | UID 10001, loopback only, read-only root, effective and bounding capabilities zero, NoNewPrivs=1. |
| Resource limits | memory.max=536870912, cpu.max=100000 100000, pids.max=128. |
| Mount and DockerToolMesh | Disposable bind mount listed only fixture.txt; the adapter returned its expected contents. Evidence covers the bind-mount fixture, not named-volume subpaths. |
| Timeout and cleanup | A 20-second benign sleep with a 3-second budget returned timed_out=true, ok=false, exit 124. No new container for the image remained relative to the pre-probe inventory. |
| No host fallback | Docker endpoint 127.0.0.1:1 refused the connection; the sandbox returned ok=false, exit 1, and the probe marker was absent. |

The Docker scratch directory was cleaned by the probe. The existing shared image was retained. No ports were published and no Worker, REA, Compose service, or orchestrator wiring was exercised.

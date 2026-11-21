# Stage 07 Phase 1 security disposition

GENERATED BUILD MATERIAL — DEPLOYMENT EXPOSURE UNRESOLVED — SECURITY HOLD

No token/key values are included. No rotation, deletion, suppression, image build, deployment or external token validation performed.

## Scope and evidence

Baseline f576e4d51876542397c24556aeb412861aeeae17. Initial implementation 9f6395d1d35b199b718d3c14763b607cbe1fce8d. Current branch feat/stage07-rea-skill-hybrid-braining. No commit/push/merge is claimed.

dashboard/next.config.mjs enables standalone output. dashboard/Dockerfile builds Next.js and copies /app/.next/standalone into runtime. dashboard/.dockerignore excludes host .next, but does not remove manifests freshly generated inside the build stage. Local standalone preview and server-reference manifests exist. The exact host build is not proven to be the image build.

Docker CLI is unavailable in this environment. Local image existence, image-layer contents, registry publication and actual deployment are NOT VERIFIED. No authoritative deployment evidence was located in inspected repository reports; this does not prove no deployment occurred. External deployment systems were not accessed.

No draftMode/setPreviewData/previewData/isPreview/enableDraftMode references found in inspected dashboard/app, dashboard/components and dashboard/lib source. Absence of application references does not prove key material is non-sensitive.

Preview material is ignored and untracked. CI uses gitleaks-action with full Git checkout. Worker gitleaks wrapper provides a Git-metadata scan workspace; it does not inspect built image layers. This investigation separately scans Git history, current tracked-file snapshot, whole directory and deliverable snapshot. Image/artifact-layer scan unavailable because Docker/image access is unavailable.

## All current directory findings

| # | Rule | File:line | Classification | Baseline tracked | Stage 07 introduced |
|---:|---|---|---|---|---|
| 1 | generic-api-key | `.security-venv-win/Lib/site-packages/cryptography/hazmat/bindings/_rust/openssl/hpke.pyi:77` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 2 | generic-api-key | `.security-venv-win/Lib/site-packages/cryptography/hazmat/bindings/_rust/openssl/hpke.pyi:101` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 3 | generic-api-key | `.security-venv-win/Lib/site-packages/google/protobuf/descriptor_pb2.py:34` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 4 | generic-api-key | `.security-venv-win/Lib/site-packages/jwt/algorithms.py:97` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 5 | generic-api-key | `.security-venv-win/Lib/site-packages/jwt/algorithms.py:984` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 6 | generic-api-key | `.security-venv-win/Lib/site-packages/jwt/algorithms.py:1107` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 7 | generic-api-key | `.security-venv-win/Lib/site-packages/win32/lib/win32cryptcon.py:1128` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 8 | generic-api-key | `.security-venv-win/Lib/site-packages/win32/lib/win32cryptcon.py:1129` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 9 | generic-api-key | `.venv/Lib/site-packages/cryptography/hazmat/bindings/_rust/openssl/hpke.pyi:77` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 10 | generic-api-key | `.venv/Lib/site-packages/cryptography/hazmat/bindings/_rust/openssl/hpke.pyi:101` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 11 | generic-api-key | `.venv/Lib/site-packages/sqlalchemy/ext/mypy/plugin.py:157` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 12 | generic-api-key | `.venv/Lib/site-packages/sqlalchemy/ext/mypy/plugin.py:259` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 13 | generic-api-key | `.venv/Lib/site-packages/sqlalchemy/ext/mypy/plugin.py:267` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 14 | generic-api-key | `.venv/Lib/site-packages/sqlalchemy/ext/mypy/decl_class.py:514` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 15 | generic-api-key | `.venv/Lib/site-packages/sqlalchemy/orm/unitofwork.py:246` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 16 | generic-api-key | `.venv/Lib/site-packages/sqlalchemy/orm/mapped_collection.py:321` | Dependency false positive: type/API identifier or constant | No; local creation date unknown | No in commit/deliverables |
| 17 | generic-api-key | `dashboard/.next/cache/.previewinfo:1` | Generated cryptographic material; SECURITY HOLD | No; local creation date unknown | No in commit/deliverables |
| 18 | generic-api-key | `dashboard/.next/cache/.previewinfo:1` | Generated cryptographic material; SECURITY HOLD | No; local creation date unknown | No in commit/deliverables |
| 19 | generic-api-key | `dashboard/.next/prerender-manifest.json:58` | Generated cryptographic material; SECURITY HOLD | No; local creation date unknown | No in commit/deliverables |
| 20 | generic-api-key | `dashboard/.next/prerender-manifest.json:59` | Generated cryptographic material; SECURITY HOLD | No; local creation date unknown | No in commit/deliverables |
| 21 | generic-api-key | `dashboard/.next/standalone/.next/prerender-manifest.json:58` | Generated cryptographic material; SECURITY HOLD | No; local creation date unknown | No in commit/deliverables |
| 22 | generic-api-key | `dashboard/.next/standalone/.next/prerender-manifest.json:59` | Generated cryptographic material; SECURITY HOLD | No; local creation date unknown | No in commit/deliverables |
| 23 | generic-api-key | `reports/d54-dockerfile-verify-20261025.md:38` | Historical report false positive: Docker tag | Yes | No in commit/deliverables |
| 24 | generic-api-key | `reports/d54-dockerfile-verify-20261025.md:117` | Historical report false positive: Docker tag | Yes | No in commit/deliverables |
| 25 | github-pat | `tests/__pycache__/test_stage04b_security.cpython-312-pytest-9.1.1.pyc:232` | Verified test fixture false positive (constant-folded source line 464) | No; local creation date unknown | No in commit/deliverables |
| 26 | github-pat | `tests/__pycache__/test_stage04b_security.cpython-312-pytest-8.3.4.pyc:232` | Verified test fixture false positive (constant-folded source line 464) | No; local creation date unknown | No in commit/deliverables |
| 27 | sourcegraph-access-token | `gitleaks-artifact/work/Astra-Hybrid-Code/Astra-Hybrid-Code/results.sarif:1288` | Verified false positive: SARIF commitSha, not Sourcegraph credential | No; local creation date unknown | No in commit/deliverables |
| 28 | sourcegraph-access-token | `gitleaks-artifact/work/Astra-Hybrid-Code/Astra-Hybrid-Code/results.sarif:1322` | Verified false positive: SARIF commitSha, not Sourcegraph credential | No; local creation date unknown | No in commit/deliverables |

Fingerprint convention: file:RuleID:StartLine. Two preview matches share one file/line; categories are signing key and encryption key. All 28 historical findings were previously context-inspected without printing matched values. Sourcegraph matches equal SARIF commitSha fields and were absent verbatim from tracked files/baseline/history. Compiled fixture values equal the source constant expression at tests/test_stage04b_security.py:464. No new suppressions added.

## Six preview findings

| Finding | Key category | Standalone inclusion | Runtime image | Deployment/exposure |
|---|---|---|---|---|
| .next/cache/.previewinfo:1 (1) | Preview signing | Duplicated category in standalone manifest | Exact host material unverified | Unknown / HOLD |
| .next/cache/.previewinfo:1 (2) | Preview encryption | Duplicated category in standalone manifest | Exact host material unverified | Unknown / HOLD |
| .next/prerender-manifest.json:58 | Preview signing | Manifest exists in standalone | Dockerfile copy path includes freshly built standalone | Unknown / HOLD |
| .next/prerender-manifest.json:59 | Preview encryption | Manifest exists in standalone | Dockerfile copy path includes freshly built standalone | Unknown / HOLD |
| .next/standalone/.next/prerender-manifest.json:58 | Preview signing | Yes, local standalone artifact | Inclusion by Dockerfile semantics; no image inspected | Unknown / HOLD |
| .next/standalone/.next/prerender-manifest.json:59 | Preview encryption | Yes, local standalone artifact | Inclusion by Dockerfile semantics; no image inspected | Unknown / HOLD |

Related server-reference encryption material exists in both local server-reference manifests; values were not printed. It is generated material outside the six detector matches and requires the same artifact/deployment review.

Recommendation: independent security reviewer must inspect an authorized image inventory and deployment history, preview/server-action use and access controls; determine whether rebuilding/rotation or artifact restrictions are required. No rotation/deletion or broader deployment access is authorized by this report. Reviewer decision PENDING. Do not label these harmless or externally compromised.

## Scanner results

| Scan | Exit | Findings |
|---|---:|---:|
| tracked files | 1 | 2 |
| Stage 07 deliverables | 0 | 0 |
| Git history | 0 | 0 |
| whole working directory | 1 | 28 |

Directory-wide Gitleaks gate HOLD/FAIL while generated cryptographic material remains unresolved. Git-history zero findings reflects existing repository configuration/suppressions, unchanged by this task. No image scan PASS is claimed.

## Exact material checks (values withheld)

- dashboard/.next/cache/.previewinfo: populated categories previewModeSigningKey, previewModeEncryptionKey.
- dashboard/.next/prerender-manifest.json: populated categories previewModeSigningKey, previewModeEncryptionKey.
- dashboard/.next/standalone/.next/prerender-manifest.json: populated categories previewModeSigningKey, previewModeEncryptionKey.
- dashboard/.next/server/server-reference-manifest.json: populated categories encryptionKey.
- dashboard/.next/standalone/.next/server/server-reference-manifest.json: populated categories encryptionKey.
- Exact key material matches in current tracked files: 0.
- Current reconciliation: 28 directory matches; 22 verified false positives; 6 generated cryptographic-material detections on HOLD; 0 new Stage 07 findings; 0 confirmed external credentials.

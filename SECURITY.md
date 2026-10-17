# Security Policy

## Scope

Astra Coder is a local-first coding-agent control plane. Model output, repository text, tool arguments, provider responses, and external MCP data are untrusted. The security boundary is policy → typed tools → sandbox → independent verification.

## Non-negotiable controls

- Agent commands are not executed by the default tool mesh on the host. The production path requires a Docker/enterprise sandbox runner.
- Sandbox commands use `network=none`, read-only root, dropped capabilities, `no-new-privileges`, non-root identity, bounded memory/CPU/PIDs, a bounded writable worktree, and a timeout.
- Secrets are supplied through environment/secret-manager integration only. They are not stored in task prompts, audit metadata, Docker images, Git, or dashboard bundles.
- Paths are canonicalized under an approved root and symlink escapes are rejected. Commands use argv and an executable allowlist.
- The editor is single-writer and checks expected base hashes.
- Git rollback removes only an Astra task worktree and refuses the user's root worktree.
- A model cannot approve itself. Verification gates and an independent reviewer are required before success.
- Budgets, approval gates, RBAC, kill switch, timeouts, and repair limits fail closed.
- Audit records are redacted and hash chained; prompts and credentials are not logged by default.

## Known limitations

Docker is defense in depth, not a proof against a compromised host kernel, malicious daemon, privileged operator, or unsafe image. Release deployments must pin trusted image digests, isolate the Docker daemon, use dedicated hosts or stronger sandbox providers where required, and restrict mounts.

The dashboard is built as static output. The repository currently locks Next.js 14 per the product contract; the current npm advisory database reports vulnerabilities whose fixed versions require a later Next major. Do not expose the dashboard build with a Next server runtime until that locked-version decision is revisited.

The current environment used for development did not provide Python 3.12, Docker, Semgrep, or gitleaks, so those gates are recorded as unavailable rather than silently passed.

## Reporting

Do not open a public issue for a suspected vulnerability. Contact the repository owner privately with: affected commit/version, reproduction steps, impact, and a minimal safe proof. Never include credentials or private customer data.

## Security test expectations

Before a release, run the full adversarial suite, Semgrep, gitleaks history detection, Docker sandbox integration tests, path/symlink/command-injection tests, policy bypass tests, rollback preservation tests, and a clean-clone build.

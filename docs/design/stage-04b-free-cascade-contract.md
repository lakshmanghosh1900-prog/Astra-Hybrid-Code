# Stage 04b — Free-Cascade Model Gateway: Architecture & Integration Contract

Status: **design only, not implemented**
Branch: `feat/v1.0.1-free-cascade`
Base: `main` @ `30be0c025be7f786f5763cb2085f44cada38f812`
Tag baseline: `v1.0.0` @ `7bfd5f538ac913d6b5fb80cfc76073b7689cc4e6`
Stage HEAD at authoring: `43439cad69fd6af9b9fb2b68a97b48c8de9b7daf`

This document is the reviewable contract for the post-v1.0.0 free-tier cascade work. It contains no
Stage 04b implementation code. No source, test, config, environment file, report, or lockfile is
changed by this stage. Nothing is pushed. `main` and `v1.0.0` are untouched.

Canonical source: Report B structure + 12 conflict rulings (Appendix A) + 4 locked operator
decisions (Section 10, D-1..D-4). Where Report A and Report B diverged, Appendix A is authoritative.
Rejected alternatives in Section 10.3 must not be reintroduced.

---

## 0. Scope, invariants, and non-goals

### 0.1 Goal

Extend the existing Stage 04 gateway so that Astra Coder can plan with:

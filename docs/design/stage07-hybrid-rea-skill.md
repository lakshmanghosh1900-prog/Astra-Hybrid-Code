# Stage 07 hybrid REA skill

Planner and coder providers return data only. HybridRoleAdapter validates strict
contracts, uses the existing bounded AstraAgent coding host, and accepts transport
callbacks wrapping the existing free_cascade gateway. No provider is given shell,
file, or execution callbacks. Model names describe roles, not verified vendor identity.

Plans use sorted-key, compact JSON UTF-8 SHA-256. Approval is supplied separately
by the trusted human approval host as an exact digest; model approval assertions
are not accepted. Each patch binds the plan, step, diff digest and mandatory skill.
Allowed paths are exact files. Exclusions apply to entire subtrees. Absolute paths,
traversal, symlink escapes, REA internals and Stage 05b evidence are denied.

execute_patch calls the unchanged Stage 05b enforcement API, requiring R1/R2/R3 and
RBAC scope binding. Its audit log is mandatory and external. A hash-chained intent
receipt binding plan/step/diff must succeed before a target is written. Audit failure
raises and prevents mutation. Existing receipts retain their Stage 05b gate envelope;
STAGE07_PATCH_INTENT identifies the wrapper event. Intent is not proof of completion.

Only plain single-file unified patches with explicit hunk counts are supported.
Creation, deletion, renames, binary diffs and shell execution are unsupported and
fail closed. Verification commands are proposals only; this API never runs them.
The trusted host must serialize writers and exclude hostile local filesystem writers;
this is a capability boundary, not an operating-system sandbox. Transport callbacks
are trusted application code. Live provider execution and certification are not claimed.

Independent security review and explicit human sign-off are required before merge.

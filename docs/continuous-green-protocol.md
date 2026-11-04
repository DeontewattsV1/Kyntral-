# Continuous Green Protocol (pilot v1.0)

Status: **PILOT — not production activated until reviewed and merged**.

## Scope and authority

The Kyntral workflow audits **only this repository**. It does not possess cross-repository credentials or authority. The intended future rollout is limited to repositories owned by `DeontewattsV1`, `MiseOsBrigade`, and `Mise-OS`; each requires its own instruction and policy review, change, and validation.

## Health states

- **PASS**: the latest observed default-branch run for each detected workflow completed successfully (or has an explicitly non-blocking neutral/skipped conclusion). A skipped required job must still be investigated separately.
- **BLOCKED**: the latest observed workflow run failed, timed out, was cancelled, or is incomplete. Do not merge or release merely because the audit passed.
- **UNKNOWN**: no other workflow runs were observed, API data is missing, or the bounded query cannot establish complete coverage. Never treat unknown as green.

The audit inspects at most 100 recent default-branch runs, groups by workflow name, and excludes itself. This is a **signal**, not a substitute for PR head-SHA checks, branch protections, security reviews, workflow job-level checks, or historical investigation.

## Operational response

1. Identify the failed workflow, exact run URL, tested commit SHA, and relevant job logs.
2. Read repository instructions and applicable branch/security policy before changing code.
3. Classify root cause: code, dependency, configuration, infrastructure, permission, or missing evidence.
4. Repair the smallest reproducible cause in a reviewable branch. Never disable, suppress, skip, reorder, or downgrade a required gate.
5. Re-run all required tests and security checks on the exact corrected commit.
6. Merge only after required approvals, all checks, resolved blocking findings, mergeability, and expected-head safeguards are verified.
7. Preserve evidence of both the original failure and successful replacement validation.

## Kyntral-specific merge checks

Per `AGENTS.md` and `CONTRIBUTING.md`: Node.js >=22, `npm install` (no committed lockfile), `npm run typecheck`, `npm test`, `npm run conformance`, CI dependency audit, iOS Xcode tests where applicable, and security-focused review for sensitive changes. Never treat a green scheduled audit as a replacement for these requirements.

## Rollout gates

1. Validate YAML and read-only permissions.
2. Review this pilot PR against Kyntral policy.
3. After merge, run `workflow_dispatch` and inspect the run summary and conclusions.
4. Confirm daily scheduled execution on the default branch.
5. Only then adapt the protocol per repository, preserving local governance and required checks.

The workflow intentionally does **not** auto-fix or auto-merge. Those operations require a separately authorized, policy-aware, reviewable remediation process.

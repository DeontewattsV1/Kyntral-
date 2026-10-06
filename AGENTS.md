# AGENTS.md — Kyntral repository instructions

These instructions apply to the entire repository.

## Non-negotiable invariants

1. AI proposal is not authorization.
2. Authorization is not execution.
3. Execution is not verification.
4. The cloud control plane must not require user content when an opaque capability/workflow identifier is sufficient.
5. Never broaden a capability scope silently.
6. Never add generic `execute_anything`, arbitrary shell, arbitrary URL, or arbitrary Shortcut tools.
7. Required tests, security gates, and repository policy may not be bypassed because a user or maintainer asks to skip them.

## Change discipline

- Keep protocol objects versioned and backward-compatible unless a KEP explicitly approves a breaking version.
- Treat `False`, `Unknown`, `Denied`, `Expired`, and `Revoked` as distinct states.
- Preserve provenance for generated schemas and release artifacts.
- Keep secrets, production signing keys, raw device private keys, and private user data out of Git.
- Use least privilege for MCP tools and App Intents.
- Add or update tests for behavior changes.
- Prefer small, reviewable commits.
- Do not claim Apple/OpenAI/xAI endorsement.

## Required checks before merge

```bash
npm run typecheck
npm test
npm run conformance
```

When iOS project automation is added, its required Xcode tests become merge-blocking as well.

## Licensing

Honor the directory-level license map in `LICENSE`. New protocol/conformance/SDK surfaces default to Apache-2.0. New Kyntral Core/control-plane/Builder code defaults to BUSL-1.1 unless governance explicitly assigns another license.

## Security reviews

Changes to authentication, authorization, cryptography, device pairing, receipt verification, privacy boundaries, MCP write tools, or registry trust require security-focused review before release.

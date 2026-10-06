# Kyntral v0.1 release gates

Kyntral v0.1 is not a production release until every mandatory gate below is satisfied with evidence.

## Automated gates

- TypeScript typecheck passes.
- Unit tests pass.
- Protocol/conformance suite passes.
- High/critical npm dependency audit is clean.
- CycloneDX SBOM generation succeeds.
- Repository secret scan succeeds.
- iOS build/test workflow passes on the supported Xcode toolchain.
- KYN-W01 device tests pass without private payload entering the control plane.

## Security/protocol gates

- KCJ-1 and crypto vectors are frozen.
- Action authorization, nonce consumption, time/skew checks, revocation, and exact receipt binding are verified.
- OAuth resource/audience and per-operation scopes are enforced.
- Security review finds no unresolved release-blocking issue.

## External/platform gates

- Stable HTTPS Streamable HTTP MCP endpoint is deployed.
- OAuth issuer/introspection configuration is production-backed.
- `mcp.json` no longer points at `.invalid`.
- OpenAI plugin flow passes positive/negative review tests.
- Grok/xAI remote MCP flow passes the same semantic vectors.
- Provider identity does not change Kyntral authorization decisions.
- TestFlight/device validation passes.

## Governance/legal gates

- Active main-branch ruleset requires CI and CODEOWNERS review and blocks force pushes/deletion.
- Signed commits are required where the platform/workflow supports enforcement.
- Final CLA and BUSL Additional Use Grant have qualified legal review.
- Trademark policy and launch claims have legal/brand review.

## Launch gate

Product Hunt remains unscheduled until all installability, integration, security, privacy, legal, and conformance gates above are satisfied.

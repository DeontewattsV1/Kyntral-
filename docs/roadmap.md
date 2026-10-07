# Kyntral implementation roadmap

This roadmap is ordered by trust boundary. A checked box means executable repository evidence exists; it does **not** imply an external platform or production-service gate is complete.

## Phase 0 — provenance and invariants

- [x] public repository and initial provenance history
- [x] protocol schema namespace
- [x] privacy non-collection invariant
- [x] mixed-license/governance scaffold
- [x] CI for typecheck, tests, conformance, dependency audit, SBOM, and secret scan
- [x] fail-closed authorization-state model
- [x] shared personal-device Shortcut documented in onboarding

## Phase 1 — authorization and durable control plane

- [x] OAuth 2.1 resource-server validation and exact-resource binding
- [x] opaque user/account subject binding
- [x] durable device registry
- [x] persistent capability grants
- [x] expiration and revocation enforcement
- [x] content-minimal durable job/action/receipt storage
- [x] replay protection and idempotency stores
- [x] per-tool/per-route scopes
- [x] paired-device HTTP possession proofs
- [ ] production OAuth authorization server / issuer configured
- [ ] production durable database deployment and operational backup policy

## Phase 2 — device trust

- [x] iOS P-256 signing identity
- [x] separate iOS P-256 key-agreement identity
- [x] device-local Keychain/Secure Enclave-backed key persistence where supported
- [x] one-time pairing challenge
- [x] device-signed pairing proof
- [x] server action-signing key pinning during pairing
- [x] action-envelope signature verification
- [x] signed execution receipts
- [x] exact action-to-receipt cryptographic binding
- [x] retry-safe execution journal
- [ ] physical-device pairing and execution evidence against production infrastructure

## Phase 3 — local runtime

- [x] Xcode application and XCTest targets
- [x] App Intents / App Shortcuts
- [x] local workflow registry
- [x] exact local standing-grant UI/state
- [x] security-scoped Files/iCloud destination bookmark
- [x] local workflow-input inbox
- [x] source/content dedupe ledger
- [x] KYN-W01 Media Intake
- [x] Personal Device API pair/check/run/revoke controls
- [ ] BGTaskScheduler / unattended delivery path validated under iOS scheduling constraints
- [ ] TestFlight and physical-device validation

## Phase 4 — model surfaces

- [x] portable plugin package structure
- [x] provider-neutral authorization normalization/conformance
- [ ] stable production HTTPS Streamable HTTP MCP endpoint
- [ ] replace reserved `.invalid` URL in `mcp.json`
- [ ] OpenAI Plugin Directory positive/negative interoperability tests
- [ ] Grok/xAI remote MCP positive/negative interoperability tests
- [ ] mobile plugin validation

## Phase 5 — developer ecosystem

- [x] Capability Manifest v1 frozen
- [x] Apache-2.0 TypeScript SDK RC surface
- [x] extension examples
- [x] Kyntral Builder browser prototype
- [x] registry certification tiers
- [x] registry prototype index
- [x] Kyntral Enhancement Proposal workflow
- [x] protocol/security/privacy changes require KEP review by governance policy
- [ ] final contributor-license agreement approved by counsel and acceptance workflow activated
- [ ] third-party extension certification exercised on an external publisher

## Phase 6 — repository governance

- [x] CODEOWNERS file
- [x] desired `main` ruleset stored as code
- [x] CI status checks exist
- [x] dependency/SBOM/secret scanning
- [ ] actual GitHub `main` branch/ruleset protection enabled
- [ ] CI and CODEOWNERS approval enforced by GitHub
- [ ] signed commits enforced where practical
- [ ] force pushes and branch deletion blocked by active GitHub rules

## Phase 7 — product and launch

- [x] privacy policy source
- [x] support path source
- [x] pre-release terms source
- [x] landing-page source
- [x] Product Hunt launch plan
- [ ] landing page deployed on canonical Kyntral domain
- [ ] final Kyntral mark and export-ready brand assets
- [ ] qualified legal review of BUSL Additional Use Grant, CLA, trademark policy, and service terms
- [ ] demo video and Product Hunt gallery
- [ ] security review with zero unresolved release-blocking findings
- [ ] architecture paper
- [ ] Product Hunt scheduled/launched

## Release invariant

```text
AI proposal != authorization != execution != verification
```

and:

```text
Kyntral Cloud should not need user content to authorize device work.
```

Kyntral v0.1 must not be represented as production-ready until every mandatory gate in `docs/release-gates.md` is evidenced.

# Kyntral implementation roadmap

This roadmap is intentionally ordered by trust boundary, not marketing surface.

## Phase 0 — provenance and invariants

- [x] public repository and signed initial commit
- [x] protocol schema namespace
- [x] privacy non-collection invariant
- [x] mixed-license/governance scaffold
- [x] CI for typecheck, tests, and conformance
- [x] fail-closed authorization state model

## Phase 1 — real authorization

- [ ] OAuth 2.1 identity integration
- [ ] user/account subject binding
- [ ] device registry
- [ ] capability-grant persistence
- [ ] expiration/revocation enforcement
- [ ] audit event minimization
- [ ] replay protection + idempotency store

## Phase 2 — device trust

- [ ] iOS signing key generation
- [ ] iOS key-agreement key generation
- [ ] Secure Enclave/Keychain persistence where supported
- [ ] one-time pairing challenge
- [ ] device-signed pairing proof
- [ ] action-envelope signature verification
- [ ] signed execution receipts

## Phase 3 — local runtime

- [ ] Xcode application target
- [ ] App Intents target
- [ ] local workflow database
- [ ] standing-grant UI
- [ ] background task integration
- [ ] approved iCloud destination handles
- [ ] KYN-W01 Media Intake

## Phase 4 — model surfaces

- [ ] production HTTPS MCP endpoint
- [ ] OpenAI plugin authentication and private testing
- [ ] Grok/xAI MCP compatibility test
- [ ] negative routing tests
- [ ] mobile plugin validation

## Phase 5 — ecosystem

- [ ] Kyntral Builder
- [ ] SDK packages
- [ ] capability manifest tooling
- [ ] Registry prototype
- [ ] Kyntral Enhancement Proposal workflow
- [ ] third-party extension conformance

## Phase 6 — launch

- [ ] security review
- [ ] dependency audit with zero unresolved critical production vulnerabilities
- [ ] privacy/legal review
- [ ] TestFlight
- [ ] plugin submission
- [ ] architecture paper
- [ ] launch video and gallery
- [ ] Product Hunt release

A release is not launch-ready until its required checks are green and no documentation claims a capability that is still represented by a scaffold.

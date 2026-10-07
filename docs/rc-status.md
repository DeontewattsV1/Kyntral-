# Kyntral v0.1 RC status

Date: 2026-10-07

This document distinguishes repository implementation from external/platform evidence. **Implemented** means executable source/tests exist in the repository. **External gate** means the repository side exists but a third-party account, production deployment, physical device, or professional review is still required.

## Release invariants

```text
AI proposal != authorization != execution != verification
```

```text
Kyntral Cloud should not need user content to authorize device work.
```

These remain release-blocking constraints.

## Security and protocol

| Gate | Status | Evidence |
| --- | --- | --- |
| Freeze canonical JSON/signing rules | Implemented | `protocol/canonical-signing.md` |
| Normative crypto test vectors | Implemented | `protocol/test-vectors/`, `conformance/crypto-vectors.test.ts` |
| Separate signing/key-agreement identities | Implemented | protocol schema + iOS `DeviceKeyManager` + CRYPTO-003 |
| One-time pairing challenges | Implemented | pairing store/proof + iOS pairing client |
| Nonce/idempotency replay protection | Implemented | durable nonce store, device-request proofs, action verifier, execution journal |
| Expiration/skew rules | Implemented | action, pairing, device-request time windows |
| Device/grant revocation | Implemented | durable device/grant state and revoke path |
| Exact action-to-receipt binding | Implemented | signed `actionHash`, receipt verification and ingestion tests |
| Cloud payload leakage release-blocking | Implemented | PRIV-001/002/003 and cloud-object checks |

## Control plane

| Gate | Status | Evidence |
| --- | --- | --- |
| Replace in-memory jobs with durable content-minimal store | Implemented | SQLite jobs/actions/receipts/devices/grants/nonces |
| OAuth 2.1 resource-server validation | Implemented | issuer/audience/expiry/resource checks |
| Server-side scopes | Implemented | read/execute/device/pair/receipt/revoke scopes |
| Reviewable write-tool annotations | Implemented | MCP tool annotations/security schemes |
| Device possession proof for execution HTTP | Implemented | `kyntral.device-request.v1` method/path/body binding |
| Stable production HTTPS Streamable HTTP MCP | **External gate** | production host + durable production DB + production OAuth issuer required |
| Replace `.invalid` in `mcp.json` | **Blocked by previous gate** | intentionally remains reserved |

## Personal device / iOS

| Gate | Status | Evidence |
| --- | --- | --- |
| Committed Xcode/XCTest project | Implemented | `ios/Kyntral.xcodeproj` |
| Entitlements file / least-privilege capability posture | Implemented for RC | current workflow uses user-selected security-scoped Files/iCloud destination; Apple distribution capability provisioning remains external |
| Local device private keys | Implemented | Keychain/Secure Enclave-aware P-256 storage |
| Device pairing | Implemented | one-time challenge + local proof + pinned server action key |
| Local workflow registry / standing grants | Implemented | exact scope/workflow/capability/risk state |
| App Intents / App Shortcuts | Implemented | stage/run/media-intake intents |
| Shared personal-device Shortcut | Implemented onboarding artifact | https://www.icloud.com/shortcuts/effa6cac2e9b4702bed9128a8749e1f8 |
| User API pair/check/run/revoke UI | Implemented | iOS Personal Device API section |
| Local source/content dedupe | Implemented | local dedupe ledger |
| Signed receipt generation | Implemented | device ES256 receipt signer |
| Retry-safe no-duplicate execution | Implemented | execution journal resubmits existing receipt |
| KYN-W01 without cloud private payload | Implemented | private URL inbox + opaque workflow action |
| Background unattended scheduling | Not yet RC-complete | BGTaskScheduler/system scheduling validation remains |
| TestFlight / physical-device E2E | **External gate** | Apple signing/TestFlight + physical iPhone required |

## Integrations

| Gate | Status | Evidence |
| --- | --- | --- |
| Portable plugin package | Implemented | root `plugin.json` + `mcp.json`; compatibility manifest |
| Private Kyntral RC plugin | Implemented | skills-only development plugin |
| OpenAI live MCP/Directory test | **External gate** | blocked by production HTTPS MCP + production OAuth |
| Grok/xAI remote MCP test | **External gate** | blocked by same public MCP endpoint |
| Provider-neutral authorization semantics | Implemented | `conformance/provider-neutrality.test.ts` |
| `kyntral.grok.me` as authority | **Not trusted/claimed** | presentation/integration surface only unless independently connected to the production trust chain |

## Developer ecosystem

| Gate | Status | Evidence |
| --- | --- | --- |
| Capability Manifest v1 frozen | Implemented | JSON Schema |
| Extension examples | Implemented | media-intake + local-file-sort |
| Apache-2.0 SDK RC | Implemented | `sdk/src/index.ts` + CAP-001 |
| Builder prototype | Implemented | static browser manifest generator under `builder/` |
| Registry review/certification tiers | Implemented | `registry/CERTIFICATION.md` |
| Registry prototype | Implemented | `registry/index.json` |
| KEP review for trust/protocol/privacy | Implemented by governance policy | KEP template + accepted signing KEP |
| Contributor-license workflow | Mechanically specified, **legal gate open** | `CLA-DRAFT.md` + `docs/contributor-license-workflow.md`; external code remains non-mergeable until final CLA |

## Repository hardening

| Gate | Status | Evidence |
| --- | --- | --- |
| CI/typecheck/unit/conformance | Implemented | GitHub Actions |
| Dependency audit | Implemented | high/critical audit gate |
| SBOM | Implemented | CycloneDX generation |
| Secret scanning | Implemented | pinned Gitleaks action |
| CODEOWNERS | Implemented | repository file |
| Desired main ruleset | Stored as code | `.github/rulesets/main-release.json` |
| Actual main protection active | **External/admin gate** | GitHub currently reports `protected: false` |
| CI + CODEOWNERS enforced by GitHub | **Blocked by protection gate** | not active |
| Required signed commits | **Blocked/not enforced** | current connector-created commits are unsigned |
| Force-push / deletion blocking | **Blocked by protection gate** | desired rules exist but are not active |

## Product and launch

| Gate | Status | Evidence |
| --- | --- | --- |
| Brand system/positioning | Implemented as design spec | `brand/BRAND.md` |
| Final export-ready visual mark/assets | Not complete | visual production/export still required |
| Landing-page source | Implemented | `site/` |
| Public RC landing preview | **Deployed** | https://kyntral-rc.vercel.app/ |
| Canonical Kyntral domain | Not complete | current deployment is RC preview under connected MiseOS Vercel team |
| Privacy policy | Implemented | `PRIVACY.md` + preview page |
| Support path | Implemented | `SUPPORT.md` + preview page |
| Service terms | Draft implemented, **legal gate open** | `TERMS.md` |
| BUSL Additional Use Grant legal review | **External legal gate** | required |
| CLA legal review | **External legal gate** | required |
| Trademark policy legal review | **External legal gate** | required |
| Demo video / Product Hunt gallery | Not complete | must follow installable/live integration evidence |
| Product Hunt scheduling | Correctly not scheduled | release gates remain |

## External blockers before v0.1 can be called production-ready

1. production OAuth authorization server/issuer;
2. production durable database and stable public HTTPS Streamable HTTP MCP deployment;
3. replace `.invalid` only after that deployment is verified;
4. live OpenAI positive/negative plugin tests;
5. live Grok/xAI positive/negative MCP tests;
6. physical iPhone + TestFlight end-to-end evidence;
7. active GitHub branch/ruleset protection and signed-commit enforcement where practical;
8. qualified legal review;
9. final visual brand assets and launch/demo assets;
10. security review with no unresolved release-blocking findings.

Until those are satisfied, the correct label is **Kyntral v0.1 Release Candidate**, not production release.

# Kyntral iOS release-candidate scaffold

SPDX-License-Identifier: BUSL-1.1

Kyntral iOS is the local execution authority. The app target is now checked in as `ios/Kyntral.xcodeproj` and the iOS workflow is intended to become merge-blocking once repository ruleset administration is enabled.

## Implemented in this boundary

- separate P-256 signing and key-agreement identities generated locally;
- private-key persistence in this-device-only Keychain storage;
- KCJ-1 canonical JSON/signing-preimage support for pairing and receipt work;
- locally generated pairing proofs from server-issued challenges;
- local workflow registry and exact-workflow standing grants;
- local URL/content dedupe ledger;
- KYN-W01 Media Intake runtime;
- explicit allowlisted HTTPS Cobalt-compatible resolver endpoint;
- App Intents/App Shortcuts for workflow validation and media intake;
- local configuration surface for resolver endpoint, destination folder, and standing grant;
- execution-receipt signer bound to an exact action hash;
- Xcode unit tests for canonicalization, key separation, dedupe, and fail-closed authorization.

## Deliberate boundaries

The application does **not** hardcode or automatically use `api.cobalt.tools`. Cobalt's current API documentation states that hosted instances such as `api.cobalt.tools` are not intended for third-party projects without explicit permission. Configure a self-hosted or explicitly authorized Cobalt-compatible HTTPS endpoint instead.

The empty entitlements file is intentional. Kyntral should request platform entitlements only when a concrete capability requires them and the capability review has approved the scope.

Secure Enclave-backed key storage remains a release-candidate follow-up. The current implementation uses separate CryptoKit P-256 identities stored in the Keychain with `AfterFirstUnlockThisDeviceOnly`, which keeps raw private keys device-local but does not yet claim hardware-backed key isolation.

The remaining end-to-end boundary is OAuth-bound device pairing and signed action-envelope verification from the production Kyntral control plane. Until that is complete, local standing grants and App Intents are valid local conformance surfaces but are not evidence that remote AI-triggered execution is production-ready.

## Release invariant

```text
AI proposal != authorization != execution != verification
```

Only `Allowed` permits execution. `Denied`, `Unknown`, `Expired`, and `Revoked` remain distinct fail-closed states.

# Kyntral iOS release-candidate status

SPDX-License-Identifier: BUSL-1.1

Kyntral iOS is the local execution authority. The checked-in Xcode project builds the SwiftUI application, App Intents, protocol/security primitives, and XCTest conformance target.

## Implemented

- separate P-256 signing and key-agreement device identities;
- Secure Enclave-first key creation with device-local software-key fallback;
- KCJ-1 canonical JSON/signing preimages shared with the protocol vectors;
- locally generated device pairing proofs from one-time server challenges;
- local workflow registry and exact-workflow standing grants;
- local URL/content dedupe ledger;
- KYN-W01 Media Intake runtime;
- explicit allowlisted HTTPS Cobalt-compatible resolver endpoint;
- App Intents / App Shortcuts for local workflow execution;
- action-bound signed execution receipts;
- local KYN-W01 configuration for resolver endpoint, destination folder, and standing grant;
- XCTest coverage for fail-closed authorization, canonical signing vectors, and dedupe semantics;
- GitHub Actions build and simulator-test gate.

## Device/content boundary

Private keys remain device-local. The standing grant for KYN-W01 applies only to the exact `wf_media_intake` / `workflow.execute` tuple; it is not arbitrary Shortcut, URL, shell, or device authority.

The media source URLs, local note contents, downloaded bytes, destination filenames, and dedupe ledger do not need to enter the Kyntral control plane. The cloud may coordinate opaque authorization metadata while the iPhone performs content-bearing work locally.

## Resolver boundary

Kyntral does not hardcode a public Cobalt deployment. Configure a self-hosted or explicitly authorized Cobalt-compatible HTTPS endpoint. The configured endpoint host becomes the local allowlist for KYN-W01.

## Remaining production boundary

The local application is not yet evidence of production remote AI-triggered execution. Before that claim, Kyntral still needs:

1. an OAuth-bound iOS pairing client against the production control plane;
2. device verification of server-authorized ActionEnvelope signatures;
3. on-device nonce/idempotency replay consumption and expiration/skew enforcement for remote actions;
4. cryptographic receipt upload and server-side receipt verification;
5. stable HTTPS Streamable HTTP MCP deployment and replacement of the reserved `.invalid` endpoint;
6. OpenAI and Grok/xAI tests against the same provider-neutral authorization semantics;
7. physical-device validation, including key lifecycle and App Shortcut behavior.

## Release invariant

```text
AI proposal != authorization != execution != verification
```

Only `Allowed` permits execution. `Denied`, `Unknown`, `Expired`, and `Revoked` remain distinct fail-closed states.

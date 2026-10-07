# Kyntral iOS release-candidate status

SPDX-License-Identifier: BUSL-1.1

Kyntral iOS is the local execution authority. The checked-in Xcode project builds the SwiftUI application, App Intents, protocol/security primitives, and XCTest conformance target.

## Implemented

- separate P-256 signing and key-agreement device identities;
- Secure Enclave-first key creation with device-local software-key fallback;
- KCJ-1 canonical JSON/signing preimages shared with the protocol vectors;
- locally generated device pairing proofs from one-time server challenges;
- OAuth-bearer device pairing/status/revocation client against the Kyntral device API;
- response binding that requires paired device/signing/key-agreement IDs to match the local identity;
- local workflow registry and exact-workflow standing grants;
- local URL/content dedupe ledger;
- KYN-W01 Media Intake runtime;
- explicit allowlisted HTTPS Cobalt-compatible resolver endpoint;
- App Intents / App Shortcuts for local workflow execution;
- device verification of signed ActionEnvelope authorization;
- durable on-device action/nonce/idempotency replay consumption and expiration/skew enforcement;
- action-bound signed execution receipts;
- local KYN-W01 configuration for resolver endpoint, destination folder, and standing grant;
- XCTest coverage for fail-closed authorization, canonical signing vectors, action verification/replay, pairing flow, and dedupe semantics;
- GitHub Actions build and simulator-test gate.

## Personal-device Shortcut

Users can install the shared Kyntral Shortcut directly on their personal device:

**[Install Kyntral Shortcut](https://www.icloud.com/shortcuts/effa6cac2e9b4702bed9128a8749e1f8)**

The intended user path is:

1. install the shared Shortcut;
2. open Kyntral on that iPhone/iPad;
3. pair the device using the Kyntral pairing flow;
4. configure the exact local workflow and standing grant;
5. use the Shortcut to stage private inputs locally;
6. allow only signed, verified Kyntral ActionEnvelopes to trigger execution.

The Shortcut is not an authorization credential. Its installation does not create a capability grant, pair a device, or bypass Kyntral's local standing-grant checks.

## Device/content boundary

Private keys remain device-local. The standing grant for KYN-W01 applies only to the exact `wf_media_intake` / `workflow.execute` tuple; it is not arbitrary Shortcut, URL, shell, or device authority.

The media source URLs, local note contents, downloaded bytes, destination filenames, and dedupe ledger do not need to enter the Kyntral control plane. The cloud may coordinate opaque authorization metadata while the iPhone performs content-bearing work locally.

The pairing client accepts an OAuth access token from the future login layer only for the duration of its request. It does not mint, invent, or persist credentials itself.

## Resolver boundary

Kyntral does not hardcode a public Cobalt deployment. Configure a self-hosted or explicitly authorized Cobalt-compatible HTTPS endpoint. The configured endpoint host becomes the local allowlist for KYN-W01.

## Remaining production boundary

The local application is not yet evidence of production remote AI-triggered execution. Before that claim, Kyntral still needs:

1. native OAuth Authorization Code + PKCE login configured against a real production authorization server/client registration;
2. production authorization-signing-key distribution/rotation and device trust anchoring;
3. cryptographic receipt upload and server-side receipt verification for the production action queue;
4. stable HTTPS Streamable HTTP MCP deployment and replacement of the reserved `.invalid` endpoint;
5. OpenAI and Grok/xAI tests against the same provider-neutral authorization semantics;
6. physical-device/TestFlight validation, including key lifecycle, pairing, revocation, background behavior, and App Shortcuts;
7. active GitHub repository protection and required-review enforcement.

No issuer, OAuth client identifier, production redirect URI, production authorization key, or MCP hostname should be invented merely to close these gates in source code.

## Release invariant

```text
AI proposal != authorization != execution != verification
```

Only `Allowed` permits execution. `Denied`, `Unknown`, `Expired`, and `Revoked` remain distinct fail-closed states.

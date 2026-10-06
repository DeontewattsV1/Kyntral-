# Kyntral Protocol v0.1

SPDX-License-Identifier: Apache-2.0

The protocol separates proposal, authorization, execution, and verification.

## Canonical object families

- `ProjectScope`
- `DeviceIdentity`
- `ActionEnvelope`
- `ExecutionReceipt`
- `CapabilityManifest`

Every serialized protocol object is explicitly versioned.

## Privacy boundary

Cloud-facing protocol objects should contain opaque identifiers and authorization metadata, not private workflow payloads. A device resolves `workflowId` locally.

## Planned cryptographic invariants

Before production release the project will freeze:

- canonical JSON representation
- signing algorithm and key representation
- device signing/key-agreement separation
- nonce format and replay store
- expiration/skew rules
- action-to-receipt binding
- immutable conformance vectors

No production security claim should be made until those rules and vectors are implemented.

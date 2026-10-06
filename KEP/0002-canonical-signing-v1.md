# KEP-0002 — Canonical signing and device identity v1

- Status: Accepted for v0.1 release-candidate implementation
- Protocol impact: yes
- Security review: required before production release
- Author: Deonte Watts
- Date: 2026-10-06

## Decision

Kyntral Protocol v1 uses KCJ-1 canonical JSON, ES256/P-256 signing, SHA-256 object hashes, and a distinct ECDH P-256 device key-agreement identity. Signing and key-agreement keys may not collapse into one identity.

The normative serialization and signature rules are in `protocol/canonical-signing.md`; deterministic conformance vectors are in `protocol/test-vectors/crypto-v1.json`.

## Security invariant

A receipt proves only the exact signed action whose `actionHash` it contains. It cannot be rebound to another action, device, workflow, scope, or principal.

## Compatibility

Changing canonicalization, signature encoding, hash preimages, purpose strings, time semantics, or key-role separation requires a new protocol version and a subsequent KEP.

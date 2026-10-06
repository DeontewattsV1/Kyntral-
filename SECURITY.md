# Security policy

Kyntral treats authorization boundaries as part of the product, not as prompt guidance.

## Report vulnerabilities

Until a dedicated security mailbox is published, open a GitHub Security Advisory for this repository rather than a public issue when the report contains exploitable details.

Do not include real user content, credentials, access tokens, private keys, device secrets, or private workflow payloads in reports.

## Security boundaries

A Kyntral action is valid only when all required dimensions are satisfied:

```text
authenticated principal
AND authorized scope
AND permitted capability
AND paired/non-revoked device
AND unexpired action
AND replay protection
AND valid signature/receipt rules
```

## Forbidden implementation patterns

- authorization derived from model text alone
- caller-selected authorization time
- reusable pairing challenges
- reusable action nonces
- private key material leaving the device
- cloud logging of Notes/files/clipboard/media payloads
- generic arbitrary command execution
- SSRF-capable unrestricted URL fetchers
- write tools mislabeled as read-only
- silent capability widening

## Cryptography

Protocol v0.1 plans separate signing and key-agreement identities. Exact algorithms and canonicalization rules must be frozen with test vectors before production use.

## Supported versions

Pre-alpha: no version is currently production-supported.

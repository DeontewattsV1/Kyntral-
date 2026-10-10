# Kyntral Canonical Signing Profile v1

SPDX-License-Identifier: Apache-2.0

**Status:** frozen for Kyntral Protocol v0.1 release-candidate work.

Kyntral signs deterministic byte sequences, not implementation-specific JSON output.

## KCJ-1 canonical JSON

Kyntral Canonical JSON Profile 1 (KCJ-1) accepts only:

- `null`
- booleans
- Unicode strings
- safe integers in the inclusive range `[-9007199254740991, 9007199254740991]`
- arrays of KCJ-1 values
- objects whose keys and values are KCJ-1 compatible

KCJ-1 rejects floating-point numbers, NaN, Infinity, BigInt, undefined values, functions, symbols, and duplicate object keys after Unicode NFC normalization.

Canonicalization rules:

1. Normalize every string and object key to Unicode NFC.
2. Sort object keys by the unsigned lexicographic ordering of their UTF-8 byte sequences.
3. Serialize strings with JSON string escaping and UTF-8 output.
4. Serialize integers in base-10 with no leading zeroes and no plus sign.
5. Emit no insignificant whitespace.
6. Preserve array order.

## Domain separation

Every signature preimage is:

```text
"KYNTRAL" || 0x00 || purpose || 0x00 || "v1" || 0x00 || KCJ-1(payload)
```

The ASCII purpose strings frozen in v1 are:

- `action-authorization`
- `execution-receipt`
- `pairing-proof`
- `device-request`

## Algorithms

Kyntral v1 uses:

- authorization/action signatures: **ES256** (ECDSA P-256 + SHA-256)
- device execution-receipt signatures: **ES256**
- pairing proof signatures: **ES256**
- device HTTP possession proofs: **ES256**
- device key agreement: **ECDH P-256**
- object hashes: **SHA-256**
- signatures: ASN.1 DER encoded ECDSA signatures, then base64url without padding
- EC public keys: JWK `kty=EC`, `crv=P-256`, base64url `x` and `y`

Signing and key-agreement identities MUST be distinct key pairs and MUST have distinct key IDs.

## Action authorization

The authorization signature covers the ActionEnvelope with `authorizationProof` omitted.

The fully signed ActionEnvelope is then canonicalized with KCJ-1 and hashed:

```text
actionHash = "sha256:" || lowercase_hex(SHA-256(KCJ-1(signedActionEnvelope)))
```

## Receipt binding

An ExecutionReceipt MUST contain the exact `actionHash` derived from the signed ActionEnvelope that authorized the work.

The device signature covers the ExecutionReceipt with `deviceProof` omitted.

Verification therefore requires all of the following:

1. the action authorization signature is valid;
2. the ActionEnvelope is temporally valid and its nonce has not been consumed;
3. the receipt `actionId` equals the action `actionId`;
4. the receipt `deviceId` equals the action `deviceId`;
5. the receipt `actionHash` equals the computed hash of the exact signed ActionEnvelope;
6. the receipt device signature verifies against the paired device signing key;
7. the paired device has not been revoked.

A valid receipt for action A is never evidence that action B executed.

## Device request possession proof

After pairing, device delivery and receipt-upload HTTP requests use
`kyntral.device-request.v1`. The signed payload binds the paired device
identity to the exact HTTP method, path, raw-body SHA-256 hash, one-time nonce,
issue time, and expiry time.

The proof is carried in the `X-Kyntral-Device-Proof` HTTP header as base64url
of its JSON representation. JSON member ordering in the header is not
authoritative; verification reconstructs the KCJ-1 unsigned projection.

A device request proof:

- has a maximum lifetime of 60 seconds;
- permits at most 30 seconds of clock skew;
- is signed by the already-paired device signing key;
- MUST match the request method, path, and raw body hash exactly;
- consumes its nonce durably after signature verification;
- MUST NOT be accepted for another device, request body, route, or method.

OAuth identifies the account and authorized client. The device request proof
separately proves possession of the paired device signing key.

## Time rules

Unless a later protocol version explicitly changes them:

- maximum action lifetime: 5 minutes;
- maximum pairing-challenge lifetime: 5 minutes;
- maximum device-request lifetime: 60 seconds;
- accepted clock skew: 60 seconds;
- an `issuedAt` more than 60 seconds in the future is invalid;
- an object is expired when current time is later than `expiresAt + 60 seconds`;
- `expiresAt` MUST be after `issuedAt`;
- nonce consumption is one-time and durable.

## Test vectors

`protocol/test-vectors/crypto-v1.json` is normative for KCJ-1 ordering,
action hashing, ES256 verification, receipt binding, distinct device identities,
and ECDH shared-secret derivation.

`protocol/test-vectors/device-request-v1.json` is normative for device-request
canonicalization, method/path/body binding, and possession-proof verification.

Private scalar values used to generate test vectors are test-only material and MUST NOT be reused in production.

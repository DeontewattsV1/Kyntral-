// SPDX-License-Identifier: BUSL-1.1

import { randomBytes, randomUUID } from "node:crypto";
import {
  signingPreimage,
  verifyEs256,
  type CanonicalJson,
  type Es256Proof,
  type P256PublicJwk
} from "./crypto.js";
import { assertOpaqueId } from "./domain.js";
import type { KyntralStore, StoredPairingChallenge } from "./store.js";
import { assertPairingTimeWindow, MAX_PAIRING_LIFETIME_MS, MAX_CLOCK_SKEW_MS } from "./time.js";

export type DeviceIdentity = Readonly<{
  version: "kyntral.device.v1";
  deviceId: string;
  platform: "ios";
  signingPublicKey: P256PublicJwk;
  keyAgreementPublicKey: P256PublicJwk;
  createdAt: string;
  revokedAt?: string;
}>;

export type PairingChallenge = Readonly<{
  version: "kyntral.pairing-challenge.v1";
  challengeId: string;
  principalId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}>;

export type PairingProof = Readonly<{
  version: "kyntral.pairing-proof.v1";
  challengeId: string;
  nonce: string;
  deviceIdentity: DeviceIdentity;
  proof: Es256Proof;
}>;

export function createPairingChallenge(
  store: KyntralStore,
  principalId: string,
  now = new Date()
): PairingChallenge {
  const safePrincipalId = assertOpaqueId(principalId, "principalId");
  const challenge: PairingChallenge = {
    version: "kyntral.pairing-challenge.v1",
    challengeId: "pair_" + randomUUID().replaceAll("-", ""),
    principalId: safePrincipalId,
    nonce: randomBytes(32).toString("base64url"),
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + MAX_PAIRING_LIFETIME_MS).toISOString()
  };

  store.putPairingChallenge({ ...challenge, consumedAt: null });
  return challenge;
}

export function pairingProofProjection(proof: PairingProof): CanonicalJson {
  const { proof: _proof, ...unsigned } = proof;
  return unsigned as unknown as CanonicalJson;
}

function assertDistinctDeviceKeys(identity: DeviceIdentity): void {
  const signing = identity.signingPublicKey;
  const agreement = identity.keyAgreementPublicKey;

  if (
    signing.kid === agreement.kid ||
    (signing.x === agreement.x && signing.y === agreement.y)
  ) {
    throw new Error("device signing and key-agreement identities must be distinct");
  }
  if (signing.use !== "sig" || signing.alg !== "ES256") {
    throw new Error("device signing key must be P-256 ES256");
  }
  if (agreement.use !== "enc" || agreement.alg !== "ECDH-ES") {
    throw new Error("device key-agreement key must be P-256 ECDH-ES");
  }
}

export function verifyAndConsumePairingProof(input: {
  store: KyntralStore;
  principalId: string;
  proof: PairingProof;
  now?: Date;
}): DeviceIdentity {
  const now = input.now ?? new Date();
  const challenge = input.store.getPairingChallenge(input.proof.challengeId);

  if (!challenge) throw new Error("unknown pairing challenge");
  if (challenge.consumedAt !== null) throw new Error("pairing challenge already consumed");
  if (challenge.principalId !== input.principalId) {
    throw new Error("pairing challenge principal mismatch");
  }
  if (challenge.nonce !== input.proof.nonce) {
    throw new Error("pairing challenge nonce mismatch");
  }

  assertPairingTimeWindow({
    issuedAt: challenge.issuedAt,
    expiresAt: challenge.expiresAt,
    now
  });

  const identity = input.proof.deviceIdentity;
  assertOpaqueId(identity.deviceId, "deviceId");
  assertDistinctDeviceKeys(identity);

  if (input.proof.proof.keyId !== identity.signingPublicKey.kid) {
    throw new Error("pairing proof keyId does not match device signing key");
  }

  const verified = verifyEs256(
    identity.signingPublicKey,
    signingPreimage("pairing-proof", pairingProofProjection(input.proof)),
    input.proof.proof.signature
  );
  if (!verified) throw new Error("invalid device pairing proof");

  const existing = input.store.getDevice(identity.deviceId);
  if (existing?.revokedAt) throw new Error("device identity is revoked");

  if (!input.store.consumePairingChallenge(challenge.challengeId, now)) {
    throw new Error("pairing challenge replay detected");
  }
  const retainUntil = new Date(Date.parse(challenge.expiresAt) + MAX_CLOCK_SKEW_MS).toISOString();
  if (!input.store.consumeNonce("pairing", challenge.nonce, retainUntil, now)) {
    throw new Error("pairing nonce replay detected");
  }

  input.store.putDevice({
    deviceId: identity.deviceId,
    principalId: input.principalId,
    identityJson: JSON.stringify(identity),
    createdAt: identity.createdAt,
    revokedAt: null
  });

  return identity;
}

export function storedChallengeToProtocol(
  challenge: StoredPairingChallenge
): PairingChallenge {
  return {
    version: "kyntral.pairing-challenge.v1",
    challengeId: challenge.challengeId,
    principalId: challenge.principalId,
    nonce: challenge.nonce,
    issuedAt: challenge.issuedAt,
    expiresAt: challenge.expiresAt
  };
}

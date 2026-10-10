// SPDX-License-Identifier: BUSL-1.1

import {
  generateKeyPairSync,
  sign,
  type JsonWebKey,
  type KeyObject
} from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { signingPreimage, type P256PublicJwk } from "../src/crypto.js";
import {
  createPairingChallenge,
  pairingProofProjection,
  verifyAndConsumePairingProof,
  type DeviceIdentity,
  type PairingProof
} from "../src/pairing.js";
import { SqliteKyntralStore } from "../src/store.js";

let store: SqliteKyntralStore | undefined;

afterEach(() => {
  store?.close();
  store = undefined;
});

function keyPair(
  use: "sig" | "enc",
  alg: "ES256" | "ECDH-ES",
  kid: string
): { privateKey: KeyObject; publicJwk: P256PublicJwk } {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" }) as JsonWebKey;
  return {
    privateKey: pair.privateKey,
    publicJwk: {
      kty: "EC",
      crv: "P-256",
      x: String(jwk.x),
      y: String(jwk.y),
      kid,
      use,
      alg
    }
  };
}

describe("device pairing", () => {
  it.each([0, 300_000, 360_000])("accepts one valid proof at offset %i and rejects challenge replay", (offset) => {
    store = new SqliteKyntralStore(":memory:");
    const now = new Date("2026-10-06T23:00:00.000Z");
    const challenge = createPairingChallenge(store, "usr_test_001", now);
    const signing = keyPair("sig", "ES256", "device_sign_001");
    const agreement = keyPair("enc", "ECDH-ES", "device_kex_001");

    const identity: DeviceIdentity = {
      version: "kyntral.device.v1",
      deviceId: "dev_test_001",
      platform: "ios",
      signingPublicKey: signing.publicJwk,
      keyAgreementPublicKey: agreement.publicJwk,
      createdAt: now.toISOString()
    };

    const unsigned: PairingProof = {
      version: "kyntral.pairing-proof.v1",
      challengeId: challenge.challengeId,
      nonce: challenge.nonce,
      deviceIdentity: identity,
      proof: {
        keyId: signing.publicJwk.kid,
        algorithm: "ES256",
        signature: "placeholder"
      }
    };

    const signature = sign(
      "sha256",
      signingPreimage("pairing-proof", pairingProofProjection(unsigned)),
      signing.privateKey
    ).toString("base64url");

    const proof: PairingProof = {
      ...unsigned,
      proof: { ...unsigned.proof, signature }
    };

    const evaluationTime = new Date(now.getTime() + offset);
    expect(() => verifyAndConsumePairingProof({
      store: store!, principalId: "usr_test_001", proof, now: new Date(NaN)
    })).toThrow(/valid timestamp/);
    expect(store.getPairingChallenge(challenge.challengeId)?.consumedAt).toBeNull();
    expect(() => verifyAndConsumePairingProof({
      store: store!, principalId: "usr_test_001", proof, now: new Date(now.getTime() + 360_001)
    })).toThrow(/expired/);

    expect(
      verifyAndConsumePairingProof({
        store,
        principalId: "usr_test_001",
        proof,
        now: evaluationTime
      }).deviceId
    ).toBe(identity.deviceId);

    expect(() =>
      verifyAndConsumePairingProof({
        store: store!,
        principalId: "usr_test_001",
        proof,
        now: evaluationTime
      })
    ).toThrow(/consumed|replay/i);
  });

  it("rejects reuse of one key for signing and key agreement", () => {
    store = new SqliteKyntralStore(":memory:");
    const now = new Date("2026-10-06T23:00:00.000Z");
    const challenge = createPairingChallenge(store, "usr_test_001", now);
    const signing = keyPair("sig", "ES256", "device_same_001");

    const identity: DeviceIdentity = {
      version: "kyntral.device.v1",
      deviceId: "dev_test_002",
      platform: "ios",
      signingPublicKey: signing.publicJwk,
      keyAgreementPublicKey: {
        ...signing.publicJwk,
        use: "enc",
        alg: "ECDH-ES"
      },
      createdAt: now.toISOString()
    };

    const proof: PairingProof = {
      version: "kyntral.pairing-proof.v1",
      challengeId: challenge.challengeId,
      nonce: challenge.nonce,
      deviceIdentity: identity,
      proof: {
        keyId: signing.publicJwk.kid,
        algorithm: "ES256",
        signature: "invalid"
      }
    };

    expect(() =>
      verifyAndConsumePairingProof({
        store: store!,
        principalId: "usr_test_001",
        proof,
        now
      })
    ).toThrow(/distinct/i);
  });
});

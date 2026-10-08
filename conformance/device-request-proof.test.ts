// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type {
  P256PublicJwk
} from "../control-plane/src/crypto.js";
import {
  deviceRequestSigningPreimage,
  sha256Bytes,
  verifyAndConsumeDeviceRequest,
  unsignedDeviceRequestProjection,
  type DeviceRequestProof
} from "../control-plane/src/device-request.js";
import { SqliteKyntralStore } from "../control-plane/src/store.js";
import {
  canonicalizeJson,
  verifyEs256
} from "../control-plane/src/crypto.js";

const vector = JSON.parse(
  readFileSync(
    new URL(
      "../protocol/test-vectors/device-request-v1.json",
      import.meta.url
    ),
    "utf8"
  )
) as {
  canonicalUnsigned: string;
  preimageHex: string;
  publicKeyJwk: P256PublicJwk;
  signedRequest: DeviceRequestProof;
};

describe("DEVICE-004 device possession request vector", () => {
  it("fails closed on an invalid clock and retains replay protection through request skew", () => {
    const store = new SqliteKyntralStore(":memory:");
    try {
      store.putDevice({
        deviceId: vector.signedRequest.deviceId, principalId: "usr_vector",
        identityJson: JSON.stringify({ signingPublicKey: vector.publicKeyJwk }),
        createdAt: vector.signedRequest.issuedAt, revokedAt: null
      });
      const verify = (now: Date) => verifyAndConsumeDeviceRequest({
        store, proof: vector.signedRequest, expectedDeviceId: vector.signedRequest.deviceId,
        method: "GET", path: vector.signedRequest.path, body: new Uint8Array(), now
      });
      expect(() => verify(new Date(NaN))).toThrow(/valid timestamp/);
      const end = Date.parse(vector.signedRequest.expiresAt) + 30_000;
      expect(() => verify(new Date(end + 1))).toThrow(/expired/);
      expect(() => verify(new Date(end))).not.toThrow();
      expect(() => verify(new Date(end))).toThrow(/replay/);
    } finally { store.close(); }
  });
  it("matches KCJ-1 and verifies the frozen ES256 signature", () => {
    expect(
      canonicalizeJson(
        unsignedDeviceRequestProjection(vector.signedRequest)
      )
    ).toBe(vector.canonicalUnsigned);
    expect(
      deviceRequestSigningPreimage(
        vector.signedRequest
      ).toString("hex")
    ).toBe(vector.preimageHex);
    expect(
      verifyEs256(
        vector.publicKeyJwk,
        deviceRequestSigningPreimage(vector.signedRequest),
        vector.signedRequest.proof.signature
      )
    ).toBe(true);
  });

  it("freezes the empty-body hash used by action polling", () => {
    expect(sha256Bytes(new Uint8Array())).toBe(
      "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });
});

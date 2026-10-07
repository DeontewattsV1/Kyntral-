// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type {
  P256PublicJwk
} from "../control-plane/src/crypto.js";
import {
  deviceRequestSigningPreimage,
  sha256Bytes,
  unsignedDeviceRequestProjection,
  type DeviceRequestProof
} from "../control-plane/src/device-request.js";
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

// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  actionAuthorizationPreimage,
  computeActionHash,
  receiptSigningPreimage,
  verifyActionAuthorization,
  verifyReceiptBinding,
  type ExecutionReceipt,
  type P256PublicJwk,
  type SignedActionEnvelope
} from "../control-plane/src/crypto.js";

const vectors = JSON.parse(
  readFileSync(
    new URL("../protocol/test-vectors/crypto-v1.json", import.meta.url),
    "utf8"
  )
) as {
  actionPreimageHex: string;
  authorizationPublicKeyJwk: P256PublicJwk;
  signedAction: SignedActionEnvelope;
  actionHash: string;
  receiptPreimageHex: string;
  deviceSigningPublicKeyJwk: P256PublicJwk;
  deviceKeyAgreementPublicKeyJwk: P256PublicJwk;
  signedReceipt: ExecutionReceipt;
};

describe("CRYPTO-001 canonical action authorization", () => {
  it("matches and verifies the normative vector", () => {
    expect(actionAuthorizationPreimage(vectors.signedAction).toString("hex"))
      .toBe(vectors.actionPreimageHex);
    expect(
      verifyActionAuthorization(
        vectors.signedAction,
        vectors.authorizationPublicKeyJwk
      )
    ).toBe(true);
  });
});

describe("CRYPTO-002 exact action-to-receipt binding", () => {
  it("binds the receipt to the exact signed action", () => {
    expect(computeActionHash(vectors.signedAction)).toBe(vectors.actionHash);
    expect(receiptSigningPreimage(vectors.signedReceipt).toString("hex"))
      .toBe(vectors.receiptPreimageHex);
    expect(
      verifyReceiptBinding(
        vectors.signedAction,
        vectors.signedReceipt,
        vectors.deviceSigningPublicKeyJwk
      )
    ).toBe(true);
  });
});

describe("CRYPTO-003 device key separation", () => {
  it("uses distinct signing and key-agreement identities", () => {
    expect(vectors.deviceSigningPublicKeyJwk.kid)
      .not.toBe(vectors.deviceKeyAgreementPublicKeyJwk.kid);
    expect(vectors.deviceSigningPublicKeyJwk.x)
      .not.toBe(vectors.deviceKeyAgreementPublicKeyJwk.x);
    expect(vectors.deviceSigningPublicKeyJwk.y)
      .not.toBe(vectors.deviceKeyAgreementPublicKeyJwk.y);
  });
});

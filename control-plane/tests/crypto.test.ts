// SPDX-License-Identifier: BUSL-1.1

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  actionAuthorizationPreimage,
  canonicalizeJson,
  computeActionHash,
  receiptSigningPreimage,
  verifyActionAuthorization,
  verifyReceiptBinding,
  type ExecutionReceipt,
  type P256PublicJwk,
  type SignedActionEnvelope
} from "../src/crypto.js";

const vectors = JSON.parse(
  readFileSync(
    new URL("../../protocol/test-vectors/crypto-v1.json", import.meta.url),
    "utf8"
  )
) as {
  canonicalActionUnsigned: string;
  actionPreimageHex: string;
  authorizationPublicKeyJwk: P256PublicJwk;
  signedAction: SignedActionEnvelope;
  actionHash: string;
  canonicalReceiptUnsigned: string;
  receiptPreimageHex: string;
  deviceSigningPublicKeyJwk: P256PublicJwk;
  signedReceipt: ExecutionReceipt;
};

describe("KCJ-1", () => {
  it("normalizes and sorts object keys deterministically", () => {
    expect(
      canonicalizeJson({
        z: 2,
        a: 1,
        nested: { b: true, a: null }
      })
    ).toBe('{"a":1,"nested":{"a":null,"b":true},"z":2}');
  });

  it("rejects non-safe-integer numbers", () => {
    expect(() => canonicalizeJson({ value: 1.5 })).toThrow(/safe integers/i);
  });
});

describe("Kyntral crypto vectors", () => {
  it("matches the frozen action preimage", () => {
    expect(actionAuthorizationPreimage(vectors.signedAction).toString("hex"))
      .toBe(vectors.actionPreimageHex);
  });

  it("verifies the frozen authorization signature", () => {
    expect(
      verifyActionAuthorization(
        vectors.signedAction,
        vectors.authorizationPublicKeyJwk
      )
    ).toBe(true);
  });

  it("computes the exact action hash", () => {
    expect(computeActionHash(vectors.signedAction)).toBe(vectors.actionHash);
  });

  it("matches the frozen receipt preimage and binding", () => {
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

  it("rejects a receipt rebound to another action", () => {
    const altered = {
      ...vectors.signedReceipt,
      actionId: "act_other_001"
    } as ExecutionReceipt;

    expect(
      verifyReceiptBinding(
        vectors.signedAction,
        altered,
        vectors.deviceSigningPublicKeyJwk
      )
    ).toBe(false);
  });
});

// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import type {
  ExecutionReceipt,
  P256PublicJwk,
  SignedActionEnvelope
} from "../control-plane/src/crypto.js";
import { createCloudJob } from "../control-plane/src/domain.js";
import { verifyAndStoreReceipt } from "../control-plane/src/receipt.js";
import { SqliteKyntralStore } from "../control-plane/src/store.js";

const vectors = JSON.parse(
  readFileSync(
    new URL("../protocol/test-vectors/crypto-v1.json", import.meta.url),
    "utf8"
  )
) as {
  authorizationPublicKeyJwk: P256PublicJwk;
  signedAction: SignedActionEnvelope;
  actionHash: string;
  deviceSigningPublicKeyJwk: P256PublicJwk;
  deviceKeyAgreementPublicKeyJwk: P256PublicJwk;
  signedReceipt: ExecutionReceipt;
};

let store: SqliteKyntralStore | undefined;
afterEach(() => { store?.close(); store = undefined; });

function setup(): SqliteKyntralStore {
  const db = new SqliteKyntralStore(":memory:");
  db.putDevice({
    deviceId: vectors.signedAction.deviceId,
    principalId: "usr_conf_001",
    identityJson: JSON.stringify({
      signingPublicKey: vectors.deviceSigningPublicKeyJwk,
      keyAgreementPublicKey: vectors.deviceKeyAgreementPublicKeyJwk
    }),
    createdAt: "2026-10-06T22:00:00.000Z",
    revokedAt: null
  });
  db.putAuthorizedJob(createCloudJob({
    actionId: vectors.signedAction.actionId,
    deviceId: vectors.signedAction.deviceId,
    scopeId: vectors.signedAction.scopeId,
    workflowId: vectors.signedAction.workflowId,
    capability: vectors.signedAction.capability,
    risk: vectors.signedAction.risk,
    expiresAt: vectors.signedAction.expiresAt
  }), {
    action: vectors.signedAction,
    authorizationKey: vectors.authorizationPublicKeyJwk,
    actionHash: vectors.actionHash
  });
  return db;
}

describe("RECEIPT-001 exact authorization-to-receipt binding", () => {
  it("accepts the normative receipt only for its exact signed action", () => {
    store = setup();
    expect(verifyAndStoreReceipt({
      store,
      principalId: "usr_conf_001",
      receipt: vectors.signedReceipt,
      now: new Date("2026-10-06T23:01:00.000Z")
    }).status).toBe("accepted");
  });

  it("rejects recomputed-looking but unauthorized action hash changes", () => {
    store = setup();
    const altered: ExecutionReceipt = {
      ...vectors.signedReceipt,
      actionHash: "sha256:" + "a".repeat(64)
    };
    expect(() => verifyAndStoreReceipt({
      store: store!,
      principalId: "usr_conf_001",
      receipt: altered,
      now: new Date("2026-10-06T23:01:00.000Z")
    })).toThrow();
  });
});

// SPDX-License-Identifier: BUSL-1.1

import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import type {
  ExecutionReceipt,
  P256PublicJwk,
  SignedActionEnvelope
} from "../src/crypto.js";
import { createCloudJob } from "../src/domain.js";
import { verifyAndStoreReceipt } from "../src/receipt.js";
import { SqliteKyntralStore } from "../src/store.js";

const vectors = JSON.parse(
  readFileSync(
    new URL("../../protocol/test-vectors/crypto-v1.json", import.meta.url),
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

afterEach(() => {
  store?.close();
  store = undefined;
});

function setup(revokedAt: string | null = null): SqliteKyntralStore {
  const db = new SqliteKyntralStore(":memory:");
  db.putDevice({
    deviceId: vectors.signedAction.deviceId,
    principalId: "usr_receipt_001",
    identityJson: JSON.stringify({
      version: "kyntral.device.v1",
      deviceId: vectors.signedAction.deviceId,
      platform: "ios",
      signingPublicKey: vectors.deviceSigningPublicKeyJwk,
      keyAgreementPublicKey: vectors.deviceKeyAgreementPublicKeyJwk,
      createdAt: "2026-10-06T22:00:00.000Z"
    }),
    createdAt: "2026-10-06T22:00:00.000Z",
    revokedAt
  });
  const job = createCloudJob({
    actionId: vectors.signedAction.actionId,
    deviceId: vectors.signedAction.deviceId,
    scopeId: vectors.signedAction.scopeId,
    workflowId: vectors.signedAction.workflowId,
    capability: vectors.signedAction.capability,
    risk: vectors.signedAction.risk,
    expiresAt: vectors.signedAction.expiresAt
  });
  db.putAuthorizedJob(job, {
    action: vectors.signedAction,
    authorizationKey: vectors.authorizationPublicKeyJwk,
    actionHash: vectors.actionHash
  }, new Date("2026-10-06T23:00:00.000Z"));
  return db;
}

describe("execution receipt ingestion", () => {
  it("verifies and stores the exact device-signed receipt", () => {
    store = setup();
    const result = verifyAndStoreReceipt({
      store,
      principalId: "usr_receipt_001",
      receipt: vectors.signedReceipt,
      now: new Date("2026-10-06T23:01:00.000Z")
    });

    expect(result.status).toBe("accepted");
    expect(store.getJob(vectors.signedAction.actionId)?.state).toBe("completed");
    expect(store.getReceipt(vectors.signedAction.actionId)?.actionHash)
      .toBe(vectors.actionHash);
  });

  it("is idempotent for the exact same receipt", () => {
    store = setup();
    const input = {
      store,
      principalId: "usr_receipt_001",
      receipt: vectors.signedReceipt,
      now: new Date("2026-10-06T23:01:00.000Z")
    };
    expect(verifyAndStoreReceipt(input).status).toBe("accepted");
    expect(verifyAndStoreReceipt(input).status).toBe("duplicate");
  });

  it("rejects a receipt rebound to another action hash", () => {
    store = setup();
    expect(() => verifyAndStoreReceipt({
      store: store!,
      principalId: "usr_receipt_001",
      receipt: {
        ...vectors.signedReceipt,
        actionHash: "sha256:" + "0".repeat(64)
      },
      now: new Date("2026-10-06T23:01:00.000Z")
    })).toThrow(/action hash mismatch/i);
  });

  it("rejects receipts from revoked devices", () => {
    store = setup("2026-10-06T23:00:05.000Z");
    expect(() => verifyAndStoreReceipt({
      store: store!,
      principalId: "usr_receipt_001",
      receipt: vectors.signedReceipt,
      now: new Date("2026-10-06T23:01:00.000Z")
    })).toThrow(/revoked/i);
  });
});

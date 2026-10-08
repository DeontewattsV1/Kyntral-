// SPDX-License-Identifier: BUSL-1.1

import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import type {
  P256PublicJwk,
  SignedActionEnvelope
} from "../src/crypto.js";
import { createCloudJob, type CloudReceipt } from "../src/domain.js";
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
};

let store: SqliteKyntralStore | undefined;

afterEach(() => {
  store?.close();
  store = undefined;
});

describe("SqliteKyntralStore", () => {
  it("persists only content-free job metadata", () => {
    store = new SqliteKyntralStore(":memory:");
    const job = createCloudJob({
      actionId: "act_store_001",
      deviceId: "dev_store_001",
      scopeId: "scope_store_001",
      workflowId: "wf_media",
      capability: "workflow.execute",
      risk: "K2",
      expiresAt: "2026-10-06T23:05:00.000Z"
    });

    store.putJob(job, new Date("2026-10-06T23:00:00.000Z"));
    expect(store.getJob(job.actionId)).toEqual(job);
  });

  it("rejects replayed nonces durably", () => {
    store = new SqliteKyntralStore(":memory:");
    const now = new Date("2026-10-06T23:00:00.000Z");
    const expiresAt = "2026-10-06T23:05:00.000Z";

    expect(store.consumeNonce("action", "nonce_001", expiresAt, now)).toBe(true);
    expect(store.consumeNonce("action", "nonce_001", expiresAt, now)).toBe(false);
  });

  it("stores receipt binding metadata without workflow payloads", () => {
    store = new SqliteKyntralStore(":memory:");
    const receipt: CloudReceipt = {
      receiptId: "rcpt_store_001",
      actionId: "act_store_001",
      deviceId: "dev_store_001",
      actionHash: "sha256:" + "a".repeat(64),
      state: "completed",
      completed: 1,
      failed: 0,
      completedAt: "2026-10-06T23:01:00.000Z",
      deviceKeyId: "device_sign_001",
      deviceSignature: "MEUCIQexample"
    };

    store.putReceipt(receipt);
    expect(store.getReceipt(receipt.actionId)).toEqual(receipt);
  });

  it("claims one device action atomically and redelivers the same in-flight action", () => {
    store = new SqliteKyntralStore(":memory:");
    const action = vectors.signedAction;
    const job = createCloudJob({
      actionId: action.actionId,
      deviceId: action.deviceId,
      scopeId: action.scopeId,
      workflowId: action.workflowId,
      capability: action.capability,
      risk: action.risk,
      expiresAt: action.expiresAt
    });

    store.putAuthorizedJob(job, {
      action,
      authorizationKey: vectors.authorizationPublicKeyJwk,
      actionHash: vectors.actionHash
    }, new Date("2026-10-06T23:00:00.000Z"));

    const first = store.claimNextAction(
      action.deviceId,
      new Date("2026-10-06T23:01:00.000Z")
    );
    expect(first?.job.state).toBe("executing");
    expect(first?.signedAction.action).toEqual(action);

    const resumed = store.claimNextAction(
      action.deviceId,
      new Date("2026-10-06T23:06:00.000Z")
    );
    expect(resumed?.signedAction.action.actionId).toBe(action.actionId);
    expect(store.getJob(action.actionId)?.state).toBe("executing");
    expect(store.claimNextAction(action.deviceId, new Date("2026-10-06T23:06:00.001Z"))).toBeNull();
  });
});

describe("atomic pairing persistence", () => {
  it("rolls challenge and nonce back when device persistence fails", () => {
    store = new SqliteKyntralStore(":memory:");
    const now = new Date("2026-10-07T00:00:00Z");
    store.putPairingChallenge({ challengeId: "pair_atomic", principalId: "usr_atomic", nonce: "nonce_atomic", issuedAt: now.toISOString(), expiresAt: "2026-10-07T00:05:00Z", consumedAt: null });
    const device = { deviceId: "dev_atomic", principalId: "usr_atomic", identityJson: "invalid-json", createdAt: now.toISOString(), revokedAt: null };
    expect(() => store!.completePairing("pair_atomic", device, now)).toThrow();
    expect(store.getPairingChallenge("pair_atomic")?.consumedAt).toBeNull();
    expect(store.getDevice("dev_atomic")).toBeNull();
    expect(() => store!.completePairing("pair_atomic", { ...device, identityJson: "{}" }, now)).not.toThrow();
    expect(() => store!.completePairing("pair_atomic", { ...device, identityJson: "{}" }, now)).toThrow(/replay/);
  });
});

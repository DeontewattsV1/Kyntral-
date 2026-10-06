// SPDX-License-Identifier: BUSL-1.1

import { afterEach, describe, expect, it } from "vitest";
import { createCloudJob, type CloudReceipt } from "../src/domain.js";
import { SqliteKyntralStore } from "../src/store.js";

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
});

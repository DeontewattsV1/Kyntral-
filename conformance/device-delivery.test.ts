// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import type {
  P256PublicJwk,
  SignedActionEnvelope
} from "../control-plane/src/crypto.js";
import { assertNoPrivatePayload, createCloudJob } from "../control-plane/src/domain.js";
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
};

let store: SqliteKyntralStore | undefined;

afterEach(() => {
  store?.close();
  store = undefined;
});

function seed(): SqliteKyntralStore {
  const db = new SqliteKyntralStore(":memory:");
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
  db.putAuthorizedJob(job, {
    action,
    authorizationKey: vectors.authorizationPublicKeyJwk,
    actionHash: vectors.actionHash
  }, new Date("2026-10-06T23:00:00.000Z"));
  return db;
}

describe("DEVICE-001 exact content-free action delivery", () => {
  it("delivers only the signed envelope and keeps it free of private workflow payloads", () => {
    store = seed();
    const delivery = store.claimNextAction(
      vectors.signedAction.deviceId,
      new Date("2026-10-06T23:01:00.000Z")
    );
    expect(delivery).not.toBeNull();
    expect(delivery?.signedAction.action)
      .toEqual(vectors.signedAction);
    expect(() => assertNoPrivatePayload(
      delivery?.signedAction.action
    )).not.toThrow();
    expect(JSON.stringify(delivery)).not.toMatch(
      /https?:\/\/|noteText|clipboard|filename|mediaBytes|prompt|conversation/
    );
  });
});

describe("DEVICE-002 single in-flight delivery", () => {
  it("redelivers the exact in-flight action rather than claiming another action", () => {
    store = seed();
    const first = store.claimNextAction(
      vectors.signedAction.deviceId,
      new Date("2026-10-06T23:01:00.000Z")
    );
    const second = store.claimNextAction(
      vectors.signedAction.deviceId,
      new Date("2026-10-06T23:01:30.000Z")
    );
    expect(first?.signedAction.action.actionId)
      .toBe(vectors.signedAction.actionId);
    expect(second?.signedAction.action.actionId)
      .toBe(vectors.signedAction.actionId);
    expect(second?.job.state).toBe("executing");
  });
});

describe("DEVICE-003 wrong device cannot claim work", () => {
  it("returns no action for a different device identifier", () => {
    store = seed();
    expect(
      store.claimNextAction(
        "dev_other_001",
        new Date("2026-10-06T23:01:00.000Z")
      )
    ).toBeNull();
  });
});

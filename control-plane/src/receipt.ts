// SPDX-License-Identifier: BUSL-1.1

import {
  verifyActionAuthorization,
  verifyReceiptBinding,
  type ExecutionReceipt,
  type P256PublicJwk
} from "./crypto.js";
import {
  assertNoPrivatePayload,
  type CloudJob,
  type CloudReceipt
} from "./domain.js";
import type { KyntralStore } from "./store.js";
import {
  assertActionTimeWindow,
  MAX_CLOCK_SKEW_MS
} from "./time.js";

export type ReceiptVerificationResult = Readonly<{
  status: "accepted" | "duplicate";
  receipt: CloudReceipt;
}>;

function parseTime(value: string, field: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(field + " must be a valid timestamp");
  }
  return parsed;
}

function deviceSigningKey(identityJson: string): P256PublicJwk {
  const identity = JSON.parse(identityJson) as {
    signingPublicKey?: P256PublicJwk;
  };
  const key = identity.signingPublicKey;
  if (!key) throw new Error("paired device is missing signing identity");
  return key;
}

function toCloudReceipt(receipt: ExecutionReceipt): CloudReceipt {
  return {
    receiptId: receipt.receiptId,
    actionId: receipt.actionId,
    deviceId: receipt.deviceId,
    actionHash: receipt.actionHash,
    state: receipt.outcome,
    completed: receipt.counts.completed,
    failed: receipt.counts.failed,
    completedAt: receipt.completedAt,
    deviceKeyId: receipt.deviceProof.keyId,
    deviceSignature: receipt.deviceProof.signature
  };
}

function sameReceipt(a: CloudReceipt, b: CloudReceipt): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function jobStateForReceipt(
  outcome: ExecutionReceipt["outcome"]
): CloudJob["state"] {
  return outcome;
}

export function verifyAndStoreReceipt(input: {
  store: KyntralStore;
  principalId: string;
  receipt: ExecutionReceipt;
  now?: Date;
}): ReceiptVerificationResult {
  const now = input.now ?? new Date();
  assertNoPrivatePayload(input.receipt);

  const record = input.store.getSignedAction(input.receipt.actionId);
  const job = input.store.getJob(input.receipt.actionId);
  if (!record || !job) throw new Error("Unknown actionId");

  const device = input.store.getDevice(job.deviceId);
  if (!device || device.principalId !== input.principalId) {
    throw new Error("Unknown actionId");
  }
  if (device.revokedAt !== null) {
    throw new Error("receipt rejected: device is revoked");
  }

  if (!verifyActionAuthorization(record.action, record.authorizationKey)) {
    throw new Error("receipt rejected: stored action authorization is invalid");
  }
  if (record.actionHash !== input.receipt.actionHash) {
    throw new Error("receipt rejected: action hash mismatch");
  }

  const startedAt = parseTime(input.receipt.startedAt, "startedAt");
  const completedAt = parseTime(input.receipt.completedAt, "completedAt");
  if (completedAt < startedAt) {
    throw new Error("receipt rejected: completedAt precedes startedAt");
  }
  if (completedAt > now.getTime() + MAX_CLOCK_SKEW_MS) {
    throw new Error("receipt rejected: completedAt is too far in the future");
  }

  assertActionTimeWindow({
    issuedAt: record.action.issuedAt,
    expiresAt: record.action.expiresAt,
    now: new Date(startedAt)
  });

  if (!verifyReceiptBinding(
    record.action,
    input.receipt,
    deviceSigningKey(device.identityJson)
  )) {
    throw new Error("receipt rejected: device signature or action binding is invalid");
  }

  const cloudReceipt = toCloudReceipt(input.receipt);
  const existing = input.store.getReceipt(input.receipt.actionId);
  if (existing) {
    if (!sameReceipt(existing, cloudReceipt)) {
      throw new Error("receipt rejected: conflicting receipt already exists");
    }
    return { status: "duplicate", receipt: existing };
  }

  input.store.putVerifiedReceipt(
    cloudReceipt,
    jobStateForReceipt(input.receipt.outcome)
  );
  return { status: "accepted", receipt: cloudReceipt };
}

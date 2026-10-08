// SPDX-License-Identifier: BUSL-1.1

import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { assertPairingTimeWindow, assertActionTimeWindow, parseInstant, MAX_CLOCK_SKEW_MS } from "./time.js";
import type {
  AuthorizationQuery,
  CapabilityGrantRecord
} from "./authorization.js";
import type {
  P256PublicJwk,
  SignedActionEnvelope
} from "./crypto.js";
import {
  assertNoPrivatePayload,
  type CloudJob,
  type CloudReceipt
} from "./domain.js";

export type StoredPairingChallenge = Readonly<{
  challengeId: string;
  principalId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  consumedAt: string | null;
}>;

export type StoredDevice = Readonly<{
  deviceId: string;
  principalId: string;
  identityJson: string;
  createdAt: string;
  revokedAt: string | null;
}>;

export type StoredSignedAction = Readonly<{
  action: SignedActionEnvelope;
  authorizationKey: P256PublicJwk;
  actionHash: string;
}>;

export type ClaimedDeviceAction = Readonly<{
  job: CloudJob;
  signedAction: StoredSignedAction;
}>;

export interface KyntralStore {
  putJob(job: CloudJob, now?: Date): void;
  putAuthorizedJob(job: CloudJob, action: StoredSignedAction, now?: Date): void;
  getJob(actionId: string): CloudJob | null;
  getSignedAction(actionId: string): StoredSignedAction | null;
  claimNextAction(deviceId: string, now?: Date): ClaimedDeviceAction | null;
  updateJobState(actionId: string, state: CloudJob["state"]): CloudJob | null;
  putReceipt(receipt: CloudReceipt): void;
  putVerifiedReceipt(receipt: CloudReceipt, state: CloudJob["state"]): void;
  getReceipt(actionId: string): CloudReceipt | null;
  consumeNonce(namespace: string, nonce: string, expiresAt: string, now?: Date): boolean;
  putPairingChallenge(challenge: StoredPairingChallenge): void;
  getPairingChallenge(challengeId: string): StoredPairingChallenge | null;
  consumePairingChallenge(challengeId: string, now?: Date): boolean;
  completePairing(challengeId: string, device: StoredDevice, now?: Date): void;
  putDevice(device: StoredDevice): void;
  getDevice(deviceId: string): StoredDevice | null;
  revokeDevice(deviceId: string, revokedAt?: Date): boolean;
  putCapabilityGrant(grant: CapabilityGrantRecord): void;
  findCapabilityGrant(query: AuthorizationQuery): CapabilityGrantRecord | null;
  revokeCapabilityGrant(grantId: string, revokedAt?: Date): boolean;
}

type Row = Record<string, string | number | bigint | null>;

const SCHEMA = [
  "PRAGMA foreign_keys = ON;",
  "PRAGMA journal_mode = WAL;",
  "CREATE TABLE IF NOT EXISTS jobs (action_id TEXT PRIMARY KEY, device_id TEXT NOT NULL, scope_id TEXT NOT NULL, workflow_id TEXT NOT NULL, capability TEXT NOT NULL, risk TEXT NOT NULL, state TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL);",
  "CREATE TABLE IF NOT EXISTS signed_actions (action_id TEXT PRIMARY KEY, action_json TEXT NOT NULL, authorization_key_json TEXT NOT NULL, action_hash TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL);",
  "CREATE TABLE IF NOT EXISTS receipts (action_id TEXT PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, device_id TEXT NOT NULL, action_hash TEXT NOT NULL, state TEXT NOT NULL, completed INTEGER NOT NULL, failed INTEGER NOT NULL, completed_at TEXT NOT NULL, device_key_id TEXT NOT NULL, device_signature TEXT NOT NULL);",
  "CREATE TABLE IF NOT EXISTS consumed_nonces (namespace TEXT NOT NULL, nonce TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT NOT NULL, PRIMARY KEY (namespace, nonce));",
  "CREATE TABLE IF NOT EXISTS pairing_challenges (challenge_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, nonce TEXT NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT);",
  "CREATE TABLE IF NOT EXISTS devices (device_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, identity_json TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);",
  "CREATE TABLE IF NOT EXISTS capability_grants (grant_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, device_id TEXT NOT NULL, scope_id TEXT NOT NULL, workflow_id TEXT NOT NULL, capability TEXT NOT NULL, risk TEXT NOT NULL, status TEXT NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT);",
  "CREATE INDEX IF NOT EXISTS idx_grants_lookup ON capability_grants (principal_id, device_id, scope_id, workflow_id, capability, risk);"
].join("\n");

export class SqliteKyntralStore implements KyntralStore {
  readonly #db: DatabaseSync;

  constructor(path = "./data/kyntral.db") {
    if (path !== ":memory:") {
      mkdirSync(dirname(resolve(path)), { recursive: true });
    }
    this.#db = new DatabaseSync(path);
    this.#db.exec(SCHEMA);
  }

  close(): void {
    this.#db.close();
  }

  putJob(job: CloudJob, now = new Date()): void {
    assertNoPrivatePayload(job);
    this.insertJob(job, now);
  }

  putAuthorizedJob(
    job: CloudJob,
    action: StoredSignedAction,
    now = new Date()
  ): void {
    assertNoPrivatePayload(job);
    assertNoPrivatePayload(action);
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      this.insertJob(job, now);
      this.#db.prepare(
        "INSERT INTO signed_actions (action_id, action_json, authorization_key_json, action_hash, nonce, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).run(
        action.action.actionId,
        JSON.stringify(action.action),
        JSON.stringify(action.authorizationKey),
        action.actionHash,
        action.action.nonce,
        action.action.issuedAt,
        action.action.expiresAt
      );
      this.#db.exec("COMMIT");
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  private insertJob(job: CloudJob, now: Date): void {
    this.#db.prepare(
      "INSERT INTO jobs (action_id, device_id, scope_id, workflow_id, capability, risk, state, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(
      job.actionId, job.deviceId, job.scopeId, job.workflowId,
      job.capability, job.risk, job.state, job.expiresAt, now.toISOString()
    );
  }

  getJob(actionId: string): CloudJob | null {
    const row = this.#db.prepare(
      "SELECT action_id, device_id, scope_id, workflow_id, capability, risk, state, expires_at FROM jobs WHERE action_id = ?"
    ).get(actionId) as Row | undefined;
    if (!row) return null;
    return {
      actionId: String(row.action_id),
      deviceId: String(row.device_id),
      scopeId: String(row.scope_id),
      workflowId: String(row.workflow_id),
      capability: String(row.capability),
      risk: String(row.risk) as CloudJob["risk"],
      state: String(row.state) as CloudJob["state"],
      expiresAt: String(row.expires_at)
    };
  }

  getSignedAction(actionId: string): StoredSignedAction | null {
    const row = this.#db.prepare(
      "SELECT action_json, authorization_key_json, action_hash FROM signed_actions WHERE action_id = ?"
    ).get(actionId) as Row | undefined;
    if (!row) return null;
    return {
      action: JSON.parse(String(row.action_json)) as SignedActionEnvelope,
      authorizationKey: JSON.parse(String(row.authorization_key_json)) as P256PublicJwk,
      actionHash: String(row.action_hash)
    };
  }

  claimNextAction(
    deviceId: string,
    now = new Date()
  ): ClaimedDeviceAction | null {
    now.toISOString();
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const candidates = this.#db.prepare(
        "SELECT action_id FROM jobs WHERE device_id = ? AND state IN ('executing', 'queued') ORDER BY CASE state WHEN 'executing' THEN 0 ELSE 1 END, created_at ASC"
      ).all(deviceId) as Row[];
      for (const row of candidates) {
        const actionId = String(row.action_id);
        const job = this.getJob(actionId);
        const signedAction = this.getSignedAction(actionId);
        if (!job || !signedAction) throw new Error("claimed action is incomplete");
        try {
          if (parseInstant(job.expiresAt, "job.expiresAt") !==
              parseInstant(signedAction.action.expiresAt, "action.expiresAt")) continue;
          assertActionTimeWindow({ ...signedAction.action, now });
        } catch { continue; }
        if (job.state === "queued") this.updateJobState(actionId, "executing");
        const claimedJob = this.getJob(actionId)!;
        this.#db.exec("COMMIT");
        return { job: claimedJob, signedAction };
      }
      this.#db.exec("COMMIT");
      return null;
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  updateJobState(actionId: string, state: CloudJob["state"]): CloudJob | null {
    this.#db.prepare("UPDATE jobs SET state = ? WHERE action_id = ?").run(state, actionId);
    return this.getJob(actionId);
  }

  putReceipt(receipt: CloudReceipt): void {
    assertNoPrivatePayload(receipt);
    this.insertReceipt(receipt);
  }

  putVerifiedReceipt(receipt: CloudReceipt, state: CloudJob["state"]): void {
    assertNoPrivatePayload(receipt);
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      this.insertReceipt(receipt);
      this.#db.prepare("UPDATE jobs SET state = ? WHERE action_id = ?")
        .run(state, receipt.actionId);
      this.#db.exec("COMMIT");
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  private insertReceipt(receipt: CloudReceipt): void {
    this.#db.prepare(
      "INSERT INTO receipts (action_id, receipt_id, device_id, action_hash, state, completed, failed, completed_at, device_key_id, device_signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(
      receipt.actionId, receipt.receiptId, receipt.deviceId, receipt.actionHash,
      receipt.state, receipt.completed, receipt.failed, receipt.completedAt,
      receipt.deviceKeyId, receipt.deviceSignature
    );
  }

  getReceipt(actionId: string): CloudReceipt | null {
    const row = this.#db.prepare(
      "SELECT action_id, receipt_id, device_id, action_hash, state, completed, failed, completed_at, device_key_id, device_signature FROM receipts WHERE action_id = ?"
    ).get(actionId) as Row | undefined;
    if (!row) return null;
    return {
      receiptId: String(row.receipt_id),
      actionId: String(row.action_id),
      deviceId: String(row.device_id),
      actionHash: String(row.action_hash),
      state: String(row.state) as CloudReceipt["state"],
      completed: Number(row.completed),
      failed: Number(row.failed),
      completedAt: String(row.completed_at),
      deviceKeyId: String(row.device_key_id),
      deviceSignature: String(row.device_signature)
    };
  }

  consumeNonce(
    namespace: string,
    nonce: string,
    expiresAt: string,
    now = new Date()
  ): boolean {
    let expiresMs: number;
    try { expiresMs = parseInstant(expiresAt, "nonce.expiresAt"); } catch { return false; }
    const nowMs = now.getTime();
    if (!Number.isFinite(expiresMs) || !Number.isFinite(nowMs) || expiresMs < nowMs) return false;
    const result = this.#db.prepare(
      "INSERT OR IGNORE INTO consumed_nonces (namespace, nonce, expires_at, consumed_at) VALUES (?, ?, ?, ?)"
    ).run(namespace, nonce, expiresAt, now.toISOString());
    return Number(result.changes) === 1;
  }

  putPairingChallenge(challenge: StoredPairingChallenge): void {
    assertNoPrivatePayload(challenge);
    this.#db.prepare(
      "INSERT INTO pairing_challenges (challenge_id, principal_id, nonce, issued_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(
      challenge.challengeId, challenge.principalId, challenge.nonce,
      challenge.issuedAt, challenge.expiresAt, challenge.consumedAt
    );
  }

  getPairingChallenge(challengeId: string): StoredPairingChallenge | null {
    const row = this.#db.prepare(
      "SELECT challenge_id, principal_id, nonce, issued_at, expires_at, consumed_at FROM pairing_challenges WHERE challenge_id = ?"
    ).get(challengeId) as Row | undefined;
    if (!row) return null;
    return {
      challengeId: String(row.challenge_id),
      principalId: String(row.principal_id),
      nonce: String(row.nonce),
      issuedAt: String(row.issued_at),
      expiresAt: String(row.expires_at),
      consumedAt: row.consumed_at === null ? null : String(row.consumed_at)
    };
  }

  consumePairingChallenge(challengeId: string, now = new Date()): boolean {
    const challenge = this.getPairingChallenge(challengeId);
    if (!challenge || challenge.consumedAt !== null) return false;
    try {
      assertPairingTimeWindow({ ...challenge, now });
    } catch {
      return false;
    }
    const result = this.#db.prepare(
      "UPDATE pairing_challenges SET consumed_at = ? WHERE challenge_id = ? AND consumed_at IS NULL"
    ).run(now.toISOString(), challengeId);
    return Number(result.changes) === 1;
  }

  completePairing(challengeId: string, device: StoredDevice, now = new Date()): void {
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const challenge = this.getPairingChallenge(challengeId);
      if (!challenge || challenge.principalId !== device.principalId) throw new Error("pairing principal mismatch");
      const existing = this.getDevice(device.deviceId);
      if (existing && existing.revokedAt !== null) {
        throw new Error("device identity is revoked");
      }
      if (!this.consumePairingChallenge(challengeId, now)) throw new Error("pairing challenge replay detected");
      const retainUntil = new Date(parseInstant(challenge.expiresAt, "expiresAt") + MAX_CLOCK_SKEW_MS).toISOString();
      if (!this.consumeNonce("pairing", challenge.nonce, retainUntil, now)) throw new Error("pairing nonce replay detected");
      this.putDevice(device);
      this.#db.exec("COMMIT");
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  putDevice(device: StoredDevice): void {
    assertNoPrivatePayload(JSON.parse(device.identityJson));
    this.#db.prepare(
      "INSERT INTO devices (device_id, principal_id, identity_json, created_at, revoked_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(device_id) DO UPDATE SET principal_id = excluded.principal_id, identity_json = excluded.identity_json, created_at = excluded.created_at, revoked_at = excluded.revoked_at"
    ).run(
      device.deviceId, device.principalId, device.identityJson,
      device.createdAt, device.revokedAt
    );
  }

  getDevice(deviceId: string): StoredDevice | null {
    const row = this.#db.prepare(
      "SELECT device_id, principal_id, identity_json, created_at, revoked_at FROM devices WHERE device_id = ?"
    ).get(deviceId) as Row | undefined;
    if (!row) return null;
    return {
      deviceId: String(row.device_id),
      principalId: String(row.principal_id),
      identityJson: String(row.identity_json),
      createdAt: String(row.created_at),
      revokedAt: row.revoked_at === null ? null : String(row.revoked_at)
    };
  }

  revokeDevice(deviceId: string, revokedAt = new Date()): boolean {
    const result = this.#db.prepare(
      "UPDATE devices SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL"
    ).run(revokedAt.toISOString(), deviceId);
    return Number(result.changes) === 1;
  }

  putCapabilityGrant(grant: CapabilityGrantRecord): void {
    assertNoPrivatePayload(grant);
    this.#db.prepare(
      "INSERT INTO capability_grants (grant_id, principal_id, device_id, scope_id, workflow_id, capability, risk, status, issued_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(grant_id) DO UPDATE SET status = excluded.status, expires_at = excluded.expires_at, revoked_at = excluded.revoked_at"
    ).run(
      grant.grantId, grant.principalId, grant.deviceId, grant.scopeId,
      grant.workflowId, grant.capability, grant.risk, grant.status,
      grant.issuedAt, grant.expiresAt, grant.revokedAt
    );
  }

  findCapabilityGrant(query: AuthorizationQuery): CapabilityGrantRecord | null {
    const row = this.#db.prepare(
      "SELECT grant_id, principal_id, device_id, scope_id, workflow_id, capability, risk, status, issued_at, expires_at, revoked_at FROM capability_grants WHERE principal_id = ? AND device_id = ? AND scope_id = ? AND workflow_id = ? AND capability = ? AND risk = ? ORDER BY issued_at DESC LIMIT 1"
    ).get(
      query.principalId, query.deviceId, query.scopeId,
      query.workflowId, query.capability, query.risk
    ) as Row | undefined;

    if (!row) return null;
    return {
      grantId: String(row.grant_id),
      principalId: String(row.principal_id),
      deviceId: String(row.device_id),
      scopeId: String(row.scope_id),
      workflowId: String(row.workflow_id),
      capability: String(row.capability),
      risk: String(row.risk) as CapabilityGrantRecord["risk"],
      status: String(row.status) as CapabilityGrantRecord["status"],
      issuedAt: String(row.issued_at),
      expiresAt: row.expires_at === null ? null : String(row.expires_at),
      revokedAt: row.revoked_at === null ? null : String(row.revoked_at)
    };
  }

  revokeCapabilityGrant(grantId: string, revokedAt = new Date()): boolean {
    const result = this.#db.prepare(
      "UPDATE capability_grants SET status = 'Revoked', revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL"
    ).run(revokedAt.toISOString(), grantId);
    return Number(result.changes) === 1;
  }
}

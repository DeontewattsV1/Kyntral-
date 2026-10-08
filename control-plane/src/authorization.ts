// SPDX-License-Identifier: BUSL-1.1

import type { RiskClass } from "./domain.js";
import type { KyntralStore } from "./store.js";

export type AuthorizationDecision =
  | "Allowed"
  | "Denied"
  | "Unknown"
  | "Expired"
  | "Revoked";

export type AuthorizationQuery = Readonly<{
  principalId: string;
  deviceId: string;
  scopeId: string;
  workflowId: string;
  capability: string;
  risk: RiskClass;
}>;

export type CapabilityGrantRecord = Readonly<{
  grantId: string;
  principalId: string;
  deviceId: string;
  scopeId: string;
  workflowId: string;
  capability: string;
  risk: RiskClass;
  status: "Allowed" | "Denied" | "Revoked";
  issuedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
}>;

export interface AuthorizationStore {
  evaluate(query: AuthorizationQuery, now?: Date): Promise<AuthorizationDecision>;
}

export class DenyByDefaultAuthorizationStore implements AuthorizationStore {
  async evaluate(
    _query: AuthorizationQuery,
    _now = new Date()
  ): Promise<AuthorizationDecision> {
    return "Unknown";
  }
}

export class PersistentAuthorizationStore implements AuthorizationStore {
  constructor(private readonly store: KyntralStore) {}

  async evaluate(
    query: AuthorizationQuery,
    now = new Date()
  ): Promise<AuthorizationDecision> {
    const device = this.store.getDevice(query.deviceId);
    if (!device) return "Unknown";
    if (device.revokedAt !== null) return "Revoked";
    if (device.principalId !== query.principalId) return "Denied";

    const grant = this.store.findCapabilityGrant(query);
    if (!grant) return "Unknown";
    if (grant.revokedAt !== null || grant.status === "Revoked") return "Revoked";
    if (grant.status === "Denied") return "Denied";
    const nowMs = now.getTime();
    const issuedMs = Date.parse(grant.issuedAt);
    const expiresMs = grant.expiresAt === null ? null : Date.parse(grant.expiresAt);
    // Malformed persisted timestamps must never turn an explicit status into authority.
    if (!Number.isFinite(nowMs) || !Number.isFinite(issuedMs) ||
        (expiresMs !== null && (!Number.isFinite(expiresMs) || expiresMs <= issuedMs))) {
      return "Unknown";
    }
    if (issuedMs > nowMs) return "Unknown";
    if (expiresMs !== null && expiresMs < nowMs) {
      return "Expired";
    }
    return grant.status === "Allowed" ? "Allowed" : "Unknown";
  }
}

export function requireAllowed(
  decision: AuthorizationDecision
): asserts decision is "Allowed" {
  if (decision !== "Allowed") {
    throw new Error("Execution denied: authorization decision is " + decision);
  }
}

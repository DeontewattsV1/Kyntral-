// SPDX-License-Identifier: BUSL-1.1

import type { RiskClass } from "./domain.js";

export type AuthorizationDecision =
  | "Allowed"
  | "Denied"
  | "Unknown"
  | "Expired"
  | "Revoked";

export type AuthorizationQuery = Readonly<{
  deviceId: string;
  scopeId: string;
  workflowId: string;
  capability: string;
  risk: RiskClass;
}>;

export interface AuthorizationStore {
  evaluate(query: AuthorizationQuery): Promise<AuthorizationDecision>;
}

/**
 * Safe default for the public scaffold.
 *
 * A missing identity/policy backend must never silently become authorization.
 * Production deployments replace this store with an authenticated policy store.
 */
export class DenyByDefaultAuthorizationStore implements AuthorizationStore {
  async evaluate(_query: AuthorizationQuery): Promise<AuthorizationDecision> {
    return "Unknown";
  }
}

export function requireAllowed(
  decision: AuthorizationDecision
): asserts decision is "Allowed" {
  if (decision !== "Allowed") {
    throw new Error(`Execution denied: authorization decision is ${decision}`);
  }
}

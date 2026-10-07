// SPDX-License-Identifier: BUSL-1.1

import type { AuthorizationQuery } from "./authorization.js";
import {
  assertNoPrivatePayload,
  assertOpaqueId,
  type RiskClass
} from "./domain.js";

export type ProposalProvider = "openai" | "xai" | "mcp-client";

export type ProviderProposal = Readonly<{
  provider: ProposalProvider;
  traceId?: string;
  principalId: string;
  deviceId: string;
  scopeId: string;
  workflowId: string;
  capability: string;
  risk: RiskClass;
}>;

/**
 * Normalize provider transport context into the provider-neutral Kyntral
 * authorization query. Provider identity and trace metadata are deliberately
 * excluded from the authorization decision surface.
 */
export function toAuthorizationQuery(
  proposal: ProviderProposal
): AuthorizationQuery {
  assertNoPrivatePayload(proposal);

  return {
    principalId: assertOpaqueId(proposal.principalId, "principalId"),
    deviceId: assertOpaqueId(proposal.deviceId, "deviceId"),
    scopeId: assertOpaqueId(proposal.scopeId, "scopeId"),
    workflowId: assertOpaqueId(proposal.workflowId, "workflowId"),
    capability: proposal.capability,
    risk: proposal.risk
  };
}

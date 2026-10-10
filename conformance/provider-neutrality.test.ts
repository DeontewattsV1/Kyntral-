// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from "vitest";
import { PersistentAuthorizationStore } from "../control-plane/src/authorization.js";
import {
  toAuthorizationQuery,
  type ProviderProposal
} from "../control-plane/src/provider.js";
import { SqliteKyntralStore } from "../control-plane/src/store.js";

let store: SqliteKyntralStore | undefined;

afterEach(() => {
  store?.close();
  store = undefined;
});

const common = {
  principalId: "usr_provider_001",
  deviceId: "dev_provider_001",
  scopeId: "scope_provider_001",
  workflowId: "wf_media",
  capability: "workflow.execute",
  risk: "K2" as const
};

function proposal(provider: ProviderProposal["provider"]): ProviderProposal {
  return {
    provider,
    traceId: "trace_" + provider.replaceAll("-", "_"),
    ...common
  };
}

describe("AUTH-PROVIDER-001 provider-neutral authorization", () => {
  it("normalizes OpenAI and xAI proposals to the exact same authorization query", () => {
    expect(toAuthorizationQuery(proposal("openai"))).toEqual(
      toAuthorizationQuery(proposal("xai"))
    );
  });

  it("does not let provider identity change a persistent grant decision", async () => {
    store = new SqliteKyntralStore(":memory:");
    store.putDevice({
      deviceId: common.deviceId,
      principalId: common.principalId,
      identityJson: JSON.stringify({ deviceId: common.deviceId }),
      createdAt: "2026-10-07T01:00:00.000Z",
      revokedAt: null
    });
    store.putCapabilityGrant({
      grantId: "grant_provider_001",
      ...common,
      status: "Allowed",
      issuedAt: "2026-10-07T01:00:00.000Z",
      expiresAt: "2026-10-08T01:00:00.000Z",
      revokedAt: null
    });

    const authorization = new PersistentAuthorizationStore(store);
    const now = new Date("2026-10-07T01:30:00.000Z");
    const openai = await authorization.evaluate(
      toAuthorizationQuery(proposal("openai")),
      now
    );
    const xai = await authorization.evaluate(
      toAuthorizationQuery(proposal("xai")),
      now
    );

    expect(openai).toBe("Allowed");
    expect(xai).toBe("Allowed");
    expect(openai).toBe(xai);
  });
});

describe("PRIV-PROVIDER-001 provider proposals remain content-free", () => {
  it("rejects payload fields before they can reach authorization", () => {
    const unsafe = {
      ...proposal("openai"),
      payload: { noteText: "private note" }
    } as ProviderProposal & { payload: { noteText: string } };

    expect(() => toAuthorizationQuery(unsafe)).toThrow(/private payload/i);
  });
});

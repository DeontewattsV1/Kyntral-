// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  DenyByDefaultAuthorizationStore,
  PersistentAuthorizationStore,
  requireAllowed
} from "../control-plane/src/authorization.js";
import { SqliteKyntralStore } from "../control-plane/src/store.js";

describe("AUTHZ-003 persisted grant temporal integrity", () => {
  it("rejects malformed expiry and preserves denial/revocation precedence", async () => {
    const store = new SqliteKyntralStore(":memory:");
    const query = {
      principalId: "usr_temporal", deviceId: "dev_temporal", scopeId: "scope_temporal",
      workflowId: "wf_temporal", capability: "workflow.execute", risk: "K2" as const
    };
    try {
      store.putDevice({
        deviceId: query.deviceId, principalId: query.principalId,
        identityJson: "{}", createdAt: "2026-10-07T00:00:00.000Z", revokedAt: null
      });
      const auth = new PersistentAuthorizationStore(store);
      for (const status of ["Allowed", "Denied", "Revoked"] as const) {
        store.putCapabilityGrant({
          ...query, grantId: "grant_temporal", status,
          issuedAt: "2026-10-07T00:00:00.000Z", expiresAt: "invalid", revokedAt: null
        });
        const decision = await auth.evaluate(query, new Date("2026-10-07T00:10:00.000Z"));
        expect(decision).toBe(status === "Allowed" ? "Unknown" : status);
        expect(() => requireAllowed(decision)).toThrow();
      }
    } finally {
      store.close();
    }
  });
});

describe("AUTHZ-001 fail-closed authorization", () => {
  it("maps an unconfigured authorization backend to Unknown, never Allowed", async () => {
    const store = new DenyByDefaultAuthorizationStore();
    const decision = await store.evaluate({
      principalId: "usr_123",
      deviceId: "dev_123",
      scopeId: "scope_123",
      workflowId: "wf_123",
      capability: "workflow.execute",
      risk: "K2"
    });

    expect(decision).toBe("Unknown");
    expect(() => requireAllowed(decision)).toThrow();
  });
});

describe("AUTHZ-002 non-collapse states", () => {
  for (const state of ["Denied", "Unknown", "Expired", "Revoked"] as const) {
    it(`${state} remains non-authorizing`, () => {
      expect(() => requireAllowed(state)).toThrow();
    });
  }
});

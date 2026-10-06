// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  DenyByDefaultAuthorizationStore,
  requireAllowed
} from "../control-plane/src/authorization.js";

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

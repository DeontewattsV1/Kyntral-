// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from "vitest";
import {
  DenyByDefaultAuthorizationStore,
  requireAllowed,
  type AuthorizationDecision
} from "../src/authorization.js";

describe("Kyntral authorization boundary", () => {
  it("fails closed when no production authorization store is configured", async () => {
    const store = new DenyByDefaultAuthorizationStore();
    const decision = await store.evaluate({
      deviceId: "dev_test",
      scopeId: "scope_test",
      workflowId: "wf_test",
      capability: "workflow.execute",
      risk: "K2"
    });

    expect(decision).toBe("Unknown");
    expect(() => requireAllowed(decision)).toThrow(/execution denied/i);
  });

  for (const decision of ["Denied", "Unknown", "Expired", "Revoked"] as const) {
    it(`does not collapse ${decision} into Allowed`, () => {
      expect(() => requireAllowed(decision)).toThrow(
        new RegExp(decision, "i")
      );
    });
  }

  it("permits only the explicit Allowed state", () => {
    const decision: AuthorizationDecision = "Allowed";
    expect(() => requireAllowed(decision)).not.toThrow();
  });
});

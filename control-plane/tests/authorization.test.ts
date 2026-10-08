// SPDX-License-Identifier: BUSL-1.1

import { afterEach, describe, expect, it } from "vitest";
import {
  DenyByDefaultAuthorizationStore,
  PersistentAuthorizationStore,
  requireAllowed,
  type AuthorizationDecision
} from "../src/authorization.js";
import { SqliteKyntralStore } from "../src/store.js";

let store: SqliteKyntralStore | undefined;

afterEach(() => {
  store?.close();
  store = undefined;
});

const query = {
  principalId: "usr_test_001",
  deviceId: "dev_test_001",
  scopeId: "scope_test_001",
  workflowId: "wf_media",
  capability: "workflow.execute",
  risk: "K2" as const
};

describe("Kyntral authorization boundary", () => {
  it("fails closed when no production authorization store is configured", async () => {
    const auth = new DenyByDefaultAuthorizationStore();
    const decision = await auth.evaluate(query);
    expect(decision).toBe("Unknown");
    expect(() => requireAllowed(decision)).toThrow(/execution denied/i);
  });

  for (const decision of ["Denied", "Unknown", "Expired", "Revoked"] as const) {
    it("does not collapse " + decision + " into Allowed", () => {
      expect(() => requireAllowed(decision)).toThrow(
        new RegExp(decision, "i")
      );
    });
  }

  it("permits only the explicit Allowed state", () => {
    const decision: AuthorizationDecision = "Allowed";
    expect(() => requireAllowed(decision)).not.toThrow();
  });

  it.each([
    ["invalid expiry", "2026-10-06T23:00:00.000Z", "invalid", "2026-10-06T23:10:00.000Z", "Unknown"],
    ["invalid issue time", "invalid", null, "2026-10-06T23:10:00.000Z", "Unknown"],
    ["invalid clock", "2026-10-06T23:00:00.000Z", null, "invalid", "Unknown"],
    ["future issue time", "2026-10-06T23:20:00.000Z", null, "2026-10-06T23:10:00.000Z", "Unknown"],
    ["reversed interval", "2026-10-06T23:00:00.000Z", "2026-10-06T22:00:00.000Z", "2026-10-06T23:10:00.000Z", "Unknown"],
    ["empty interval", "2026-10-06T23:00:00.000Z", "2026-10-06T23:00:00.000Z", "2026-10-06T23:10:00.000Z", "Unknown"],
    ["expired grant", "2026-10-06T23:00:00.000Z", "2026-10-06T23:05:00.000Z", "2026-10-06T23:10:00.000Z", "Expired"],
    ["valid unbounded grant", "2026-10-06T23:00:00.000Z", null, "2026-10-06T23:10:00.000Z", "Allowed"]
  ])("evaluates %s without granting malformed authority", async (_label, issuedAt, expiresAt, now, expected) => {
    store = new SqliteKyntralStore(":memory:");
    store.putDevice({
      deviceId: query.deviceId, principalId: query.principalId,
      identityJson: JSON.stringify({ deviceId: query.deviceId }),
      createdAt: "2026-10-06T23:00:00.000Z", revokedAt: null
    });
    store.putCapabilityGrant({
      grantId: "grant_temporal_001", ...query, status: "Allowed",
      issuedAt: issuedAt!, expiresAt: expiresAt ?? null, revokedAt: null
    });
    const decision = await new PersistentAuthorizationStore(store).evaluate(query, new Date(now!));
    expect(decision).toBe(expected);
    if (expected !== "Allowed") expect(() => requireAllowed(decision)).toThrow();
  });

  it("binds a grant to the exact principal, device, scope, workflow and capability", async () => {
    store = new SqliteKyntralStore(":memory:");
    store.putDevice({
      deviceId: query.deviceId,
      principalId: query.principalId,
      identityJson: JSON.stringify({ deviceId: query.deviceId }),
      createdAt: "2026-10-06T23:00:00.000Z",
      revokedAt: null
    });
    store.putCapabilityGrant({
      grantId: "grant_test_001",
      ...query,
      status: "Allowed",
      issuedAt: "2026-10-06T23:00:00.000Z",
      expiresAt: "2026-10-07T23:00:00.000Z",
      revokedAt: null
    });
    const auth = new PersistentAuthorizationStore(store);
    const now = new Date("2026-10-06T23:10:00.000Z");

    expect(await auth.evaluate(query, now)).toBe("Allowed");
    expect(await auth.evaluate({ ...query, principalId: "usr_other_001" }, now))
      .toBe("Denied");
    expect(await auth.evaluate({ ...query, workflowId: "wf_other" }, now))
      .toBe("Unknown");
  });

  it("revokes authorization when the paired device is revoked", async () => {
    store = new SqliteKyntralStore(":memory:");
    store.putDevice({
      deviceId: query.deviceId,
      principalId: query.principalId,
      identityJson: JSON.stringify({ deviceId: query.deviceId }),
      createdAt: "2026-10-06T23:00:00.000Z",
      revokedAt: null
    });
    store.putCapabilityGrant({
      grantId: "grant_test_002",
      ...query,
      status: "Allowed",
      issuedAt: "2026-10-06T23:00:00.000Z",
      expiresAt: null,
      revokedAt: null
    });
    store.revokeDevice(query.deviceId, new Date("2026-10-06T23:05:00.000Z"));

    const auth = new PersistentAuthorizationStore(store);
    expect(await auth.evaluate(query, new Date("2026-10-06T23:10:00.000Z")))
      .toBe("Revoked");
  });
});

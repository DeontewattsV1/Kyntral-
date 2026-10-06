// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from "vitest";
import { assertNoPrivatePayload, createCloudJob } from "../src/domain.js";

describe("Kyntral cloud boundary", () => {
  it("creates opaque content-free jobs", () => {
    const job = createCloudJob({
      actionId: "act_test123",
      deviceId: "dev_iphone1",
      scopeId: "scope_personal",
      workflowId: "wf_media",
      capability: "workflow.execute",
      risk: "K2",
      expiresAt: "2026-10-06T23:00:00Z"
    });

    expect(job.workflowId).toBe("wf_media");
    expect(() => assertNoPrivatePayload(job)).not.toThrow();
  });

  it("rejects a URL field in cloud objects", () => {
    expect(() => assertNoPrivatePayload({
      actionId: "act_test",
      url: "https://example.com/private"
    })).toThrow(/private payload field/);
  });

  it("rejects nested private content fields", () => {
    expect(() => assertNoPrivatePayload({
      metadata: { noteText: "private" }
    })).toThrow(/private payload field/);
  });
});

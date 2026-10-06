// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { assertNoPrivatePayload } from "../control-plane/src/domain.js";

describe("PRIV-001 cloud content boundary", () => {
  it("accepts opaque authorization metadata", () => {
    expect(() => assertNoPrivatePayload({
      actionId: "act_123",
      deviceId: "dev_123",
      workflowId: "wf_media",
      capability: "workflow.execute",
      state: "queued"
    })).not.toThrow();
  });

  for (const key of ["url", "noteText", "clipboard", "filename", "mediaBytes", "prompt", "contacts"]) {
    it(`rejects forbidden cloud field: ${key}`, () => {
      expect(() => assertNoPrivatePayload({ [key]: "secret" })).toThrow();
    });
  }
});

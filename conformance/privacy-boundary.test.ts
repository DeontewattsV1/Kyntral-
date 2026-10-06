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
      state: "queued",
      actionHash: "sha256:" + "a".repeat(64)
    })).not.toThrow();
  });

  const forbiddenKeys = [
    "url", "urls", "noteText", "clipboard", "filename", "fileContents",
    "content", "body", "payload", "mediaBytes", "prompt", "conversation",
    "contacts", "photos", "attachments", "email", "phone", "latitude",
    "longitude", "password", "secret", "credential", "accessToken",
    "refreshToken"
  ];

  for (const key of forbiddenKeys) {
    it("rejects forbidden cloud field: " + key, () => {
      expect(() => assertNoPrivatePayload({ [key]: "secret" })).toThrow();
    });
  }
});

describe("PRIV-002 payload-like value detection", () => {
  for (const value of [
    "https://example.com/private",
    "file:///private/mobile/note.txt",
    "someone@example.com"
  ]) {
    it("rejects payload-like value: " + value, () => {
      expect(() => assertNoPrivatePayload({ opaque: value })).toThrow();
    });
  }
});

describe("PRIV-003 nested leakage remains release-blocking", () => {
  it("rejects private content regardless of nesting depth", () => {
    expect(() =>
      assertNoPrivatePayload({
        metadata: {
          device: {
            authorization: {
              payload: { noteText: "private" }
            }
          }
        }
      })
    ).toThrow();
  });
});

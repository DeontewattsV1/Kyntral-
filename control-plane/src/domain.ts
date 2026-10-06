// SPDX-License-Identifier: BUSL-1.1

export type RiskClass = "K0" | "K1" | "K2" | "K3" | "K4";

export type CloudJob = Readonly<{
  actionId: string;
  deviceId: string;
  scopeId: string;
  workflowId: string;
  capability: string;
  risk: RiskClass;
  state: "queued" | "executing" | "completed" | "failed" | "cancelled";
  expiresAt: string;
}>;

export type CloudReceipt = Readonly<{
  receiptId: string;
  actionId: string;
  deviceId: string;
  actionHash: string;
  state: "completed" | "partial" | "failed" | "cancelled";
  completed: number;
  failed: number;
  completedAt: string;
  deviceKeyId: string;
  deviceSignature: string;
}>;

const OPAQUE_ID = /^[a-z][a-z0-9_-]{2,127}$/i;

export function assertOpaqueId(value: string, field: string): string {
  if (!OPAQUE_ID.test(value)) {
    throw new Error(field + " must be an opaque identifier");
  }
  return value;
}

export function createCloudJob(input: {
  actionId: string;
  deviceId: string;
  scopeId: string;
  workflowId: string;
  capability: string;
  risk: RiskClass;
  expiresAt: string;
}): CloudJob {
  return Object.freeze({
    actionId: assertOpaqueId(input.actionId, "actionId"),
    deviceId: assertOpaqueId(input.deviceId, "deviceId"),
    scopeId: assertOpaqueId(input.scopeId, "scopeId"),
    workflowId: assertOpaqueId(input.workflowId, "workflowId"),
    capability: assertOpaqueId(
      input.capability.replaceAll(".", "_"),
      "capability"
    ).replaceAll("_", "."),
    risk: input.risk,
    state: "queued",
    expiresAt: input.expiresAt
  });
}

export const FORBIDDEN_CLOUD_CONTENT_KEYS = new Set([
  "url", "urls", "uri", "uris", "note", "noteTitle", "noteText",
  "clipboard", "filename", "filenames", "fileContents", "content",
  "contents", "body", "payload", "text", "message", "messages",
  "media", "mediaBytes", "prompt", "conversation", "contacts",
  "photos", "attachments", "email", "phone", "latitude", "longitude",
  "password", "secret", "credential", "credentials", "accessToken",
  "refreshToken"
]);

const FORBIDDEN_CLOUD_VALUE_PATTERNS = [
  /https?:\/\//i,
  /file:\/\//i,
  /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i
];

export function assertNoPrivatePayload(value: unknown): void {
  if (typeof value === "string") {
    if (value.length > 2048) {
      throw new Error("cloud metadata string exceeds privacy-safe size limit");
    }
    for (const pattern of FORBIDDEN_CLOUD_VALUE_PATTERNS) {
      if (pattern.test(value)) {
        throw new Error("private payload-like value is forbidden in cloud objects");
      }
    }
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) assertNoPrivatePayload(item);
    return;
  }
  if (!value || typeof value !== "object") return;

  for (const [key, nested] of Object.entries(value)) {
    if (FORBIDDEN_CLOUD_CONTENT_KEYS.has(key)) {
      throw new Error("private payload field is forbidden in cloud objects: " + key);
    }
    assertNoPrivatePayload(nested);
  }
}

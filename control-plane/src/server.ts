// SPDX-License-Identifier: BUSL-1.1

import { randomUUID } from "node:crypto";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { assertNoPrivatePayload, createCloudJob, type CloudJob } from "./domain.js";

const jobs = new Map<string, CloudJob>();

function textResult(value: unknown) {
  assertNoPrivatePayload(value);
  return {
    structuredContent: value as Record<string, unknown>,
    content: [{ type: "text" as const, text: JSON.stringify(value) }]
  };
}

export function createKyntralServer(): McpServer {
  const server = new McpServer(
    { name: "kyntral", version: "0.1.0-prealpha" },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    "kyntral_get_device",
    {
      description: "Read connection status for an already-authorized opaque Kyntral device identifier.",
      inputSchema: z.object({ deviceId: z.string().min(3).max(128) })
    },
    async ({ deviceId }) => textResult({
      deviceId,
      paired: true,
      revoked: false,
      executionAuthority: "device"
    })
  );

  server.registerTool(
    "kyntral_list_capabilities",
    {
      description: "List capability identifiers and risk classes available to an authorized Kyntral scope.",
      inputSchema: z.object({ scopeId: z.string().min(3).max(128) })
    },
    async ({ scopeId }) => textResult({
      scopeId,
      capabilities: [
        { id: "workflow.preview", risk: "K0" },
        { id: "workflow.execute", risk: "K2" },
        { id: "receipt.read", risk: "K0" }
      ]
    })
  );

  server.registerTool(
    "kyntral_preview_workflow",
    {
      description: "Preview authorization metadata for an opaque local workflow. This tool does not request workflow payloads.",
      inputSchema: z.object({
        deviceId: z.string().min(3).max(128),
        scopeId: z.string().min(3).max(128),
        workflowId: z.string().min(3).max(128)
      })
    },
    async ({ deviceId, scopeId, workflowId }) => textResult({
      deviceId,
      scopeId,
      workflowId,
      authorized: true,
      risk: "K2",
      contentLocation: "device",
      payloadRequestedByCloud: false
    })
  );

  server.registerTool(
    "kyntral_queue_workflow",
    {
      description: "Queue a specific opaque workflow on a paired device. The request contains no private workflow payload.",
      inputSchema: z.object({
        deviceId: z.string().min(3).max(128),
        scopeId: z.string().min(3).max(128),
        workflowId: z.string().min(3).max(128)
      })
    },
    async ({ deviceId, scopeId, workflowId }) => {
      const actionId = `act_${randomUUID().replaceAll("-", "")}`;
      const job = createCloudJob({
        actionId,
        deviceId,
        scopeId,
        workflowId,
        capability: "workflow.execute",
        risk: "K2",
        expiresAt: new Date(Date.now() + 5 * 60_000).toISOString()
      });
      jobs.set(actionId, job);
      return textResult(job);
    }
  );

  server.registerTool(
    "kyntral_get_job",
    {
      description: "Read the minimal state of a previously queued Kyntral action.",
      inputSchema: z.object({ actionId: z.string().min(3).max(128) })
    },
    async ({ actionId }) => {
      const job = jobs.get(actionId);
      if (!job) throw new Error("Unknown actionId");
      return textResult(job);
    }
  );

  server.registerTool(
    "kyntral_cancel_job",
    {
      description: "Cancel a queued Kyntral action by opaque action identifier.",
      inputSchema: z.object({ actionId: z.string().min(3).max(128) })
    },
    async ({ actionId }) => {
      const job = jobs.get(actionId);
      if (!job) throw new Error("Unknown actionId");
      const cancelled = Object.freeze({ ...job, state: "cancelled" as const });
      jobs.set(actionId, cancelled);
      return textResult(cancelled);
    }
  );

  server.registerTool(
    "kyntral_get_receipt",
    {
      description: "Read a content-free execution receipt summary for a completed action.",
      inputSchema: z.object({ actionId: z.string().min(3).max(128) })
    },
    async ({ actionId }) => textResult({
      actionId,
      state: "completed",
      completed: 1,
      failed: 0,
      receiptHash: "sha256:pending-device-implementation",
      deviceSignature: "pending-device-implementation"
    })
  );

  return server;
}

export const handler = createMcpHandler(createKyntralServer);
export default handler;

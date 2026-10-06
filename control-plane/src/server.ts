// SPDX-License-Identifier: BUSL-1.1

import { randomUUID } from "node:crypto";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  DenyByDefaultAuthorizationStore,
  requireAllowed,
  type AuthorizationStore
} from "./authorization.js";
import {
  assertNoPrivatePayload,
  assertOpaqueId,
  createCloudJob,
  type CloudJob,
  type CloudReceipt
} from "./domain.js";

type KyntralServerOptions = Readonly<{
  authorizationStore?: AuthorizationStore;
  jobs?: Map<string, CloudJob>;
  receipts?: Map<string, CloudReceipt>;
}>;

function textResult(value: unknown) {
  assertNoPrivatePayload(value);
  return {
    structuredContent: value as Record<string, unknown>,
    content: [{ type: "text" as const, text: JSON.stringify(value) }]
  };
}

function opaque(value: string, field: string): string {
  return assertOpaqueId(value, field);
}

export function createKyntralServer(
  options: KyntralServerOptions = {}
): McpServer {
  const authorizationStore =
    options.authorizationStore ?? new DenyByDefaultAuthorizationStore();
  const jobs = options.jobs ?? new Map<string, CloudJob>();
  const receipts = options.receipts ?? new Map<string, CloudReceipt>();

  const server = new McpServer(
    { name: "kyntral", version: "0.1.0-prealpha" },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    "kyntral_get_device",
    {
      title: "Get Kyntral device state",
      description:
        "Read the minimal state for an opaque Kyntral device identifier. " +
        "The public scaffold never assumes an unknown device is paired.",
      inputSchema: z.object({ deviceId: z.string().min(3).max(128) }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async ({ deviceId }) => textResult({
      deviceId: opaque(deviceId, "deviceId"),
      state: "unknown",
      executionAuthority: "device",
      contentLocation: "device"
    })
  );

  server.registerTool(
    "kyntral_list_capabilities",
    {
      title: "List Kyntral capabilities",
      description:
        "List capability identifiers supported by this server. " +
        "Supported does not mean granted; grants are evaluated separately.",
      inputSchema: z.object({ scopeId: z.string().min(3).max(128) }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async ({ scopeId }) => textResult({
      scopeId: opaque(scopeId, "scopeId"),
      grantState: "Unknown",
      supportedCapabilities: [
        { id: "workflow.preview", risk: "K0" },
        { id: "workflow.execute", risk: "K2" },
        { id: "receipt.read", risk: "K0" }
      ]
    })
  );

  server.registerTool(
    "kyntral_preview_workflow",
    {
      title: "Preview Kyntral workflow authorization",
      description:
        "Evaluate authorization metadata for an opaque local workflow. " +
        "The tool never requests the workflow's private payload.",
      inputSchema: z.object({
        deviceId: z.string().min(3).max(128),
        scopeId: z.string().min(3).max(128),
        workflowId: z.string().min(3).max(128)
      }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async ({ deviceId, scopeId, workflowId }) => {
      const query = {
        deviceId: opaque(deviceId, "deviceId"),
        scopeId: opaque(scopeId, "scopeId"),
        workflowId: opaque(workflowId, "workflowId"),
        capability: "workflow.execute",
        risk: "K2" as const
      };
      const decision = await authorizationStore.evaluate(query);

      return textResult({
        ...query,
        decision,
        authorized: decision === "Allowed",
        contentLocation: "device",
        payloadRequestedByCloud: false
      });
    }
  );

  server.registerTool(
    "kyntral_queue_workflow",
    {
      title: "Queue authorized Kyntral workflow",
      description:
        "Queue one specific opaque workflow on a paired device after " +
        "authorization has been explicitly evaluated as Allowed. " +
        "No private workflow payload is accepted.",
      inputSchema: z.object({
        deviceId: z.string().min(3).max(128),
        scopeId: z.string().min(3).max(128),
        workflowId: z.string().min(3).max(128)
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true
      }
    },
    async ({ deviceId, scopeId, workflowId }) => {
      const query = {
        deviceId: opaque(deviceId, "deviceId"),
        scopeId: opaque(scopeId, "scopeId"),
        workflowId: opaque(workflowId, "workflowId"),
        capability: "workflow.execute",
        risk: "K2" as const
      };
      const decision = await authorizationStore.evaluate(query);
      requireAllowed(decision);

      const actionId = `act_${randomUUID().replaceAll("-", "")}`;
      const job = createCloudJob({
        actionId,
        deviceId: query.deviceId,
        scopeId: query.scopeId,
        workflowId: query.workflowId,
        capability: query.capability,
        risk: query.risk,
        expiresAt: new Date(Date.now() + 5 * 60_000).toISOString()
      });
      jobs.set(actionId, job);
      return textResult(job);
    }
  );

  server.registerTool(
    "kyntral_get_job",
    {
      title: "Get Kyntral job",
      description: "Read the minimal content-free state of a queued Kyntral action.",
      inputSchema: z.object({ actionId: z.string().min(3).max(128) }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async ({ actionId }) => {
      const id = opaque(actionId, "actionId");
      const job = jobs.get(id);
      if (!job) throw new Error("Unknown actionId");
      return textResult(job);
    }
  );

  server.registerTool(
    "kyntral_cancel_job",
    {
      title: "Cancel Kyntral job",
      description: "Cancel a known queued Kyntral action by opaque action identifier.",
      inputSchema: z.object({ actionId: z.string().min(3).max(128) }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async ({ actionId }) => {
      const id = opaque(actionId, "actionId");
      const job = jobs.get(id);
      if (!job) throw new Error("Unknown actionId");
      const cancelled = Object.freeze({ ...job, state: "cancelled" as const });
      jobs.set(id, cancelled);
      return textResult(cancelled);
    }
  );

  server.registerTool(
    "kyntral_get_receipt",
    {
      title: "Get Kyntral execution receipt",
      description:
        "Read a content-free receipt that was actually submitted for a known action. " +
        "The scaffold never fabricates completed receipts.",
      inputSchema: z.object({ actionId: z.string().min(3).max(128) }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async ({ actionId }) => {
      const id = opaque(actionId, "actionId");
      const receipt = receipts.get(id);
      if (!receipt) throw new Error("Receipt not available");
      return textResult(receipt);
    }
  );

  return server;
}

export const handler = createMcpHandler(createKyntralServer);
export default handler;

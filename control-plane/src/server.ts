// SPDX-License-Identifier: BUSL-1.1

import { randomUUID } from "node:crypto";
import {
  McpServer,
  requireScopes,
  type AuthInfo
} from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  Es256ActionSigner,
  issueSignedAction
} from "./action.js";
import {
  PersistentAuthorizationStore,
  requireAllowed,
  type AuthorizationStore
} from "./authorization.js";
import type { ExecutionReceipt } from "./crypto.js";
import {
  assertNoPrivatePayload,
  assertOpaqueId,
  createCloudJob
} from "./domain.js";
import {
  createPairingChallenge,
  verifyAndConsumePairingProof,
  type PairingProof
} from "./pairing.js";
import { verifyAndStoreReceipt } from "./receipt.js";
import type { KyntralStore } from "./store.js";

export const KYNTRAL_SCOPES = {
  read: "kyntral.read",
  execute: "kyntral.execute",
  receiptSubmit: "kyntral.receipt.submit",
  pair: "kyntral.pair",
  revoke: "kyntral.revoke"
} as const;

type KyntralServerOptions = Readonly<{
  store: KyntralStore;
  actionSigner: Es256ActionSigner;
  authorizationStore?: AuthorizationStore;
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

function securityMeta(scopes: string[]) {
  return {
    securitySchemes: [
      {
        type: "oauth2",
        scopes
      }
    ]
  };
}

function requirePrincipal(authInfo: AuthInfo | undefined): string {
  const principal = authInfo?.extra?.kyntralPrincipalId;
  if (typeof principal !== "string") {
    throw new Error("Authenticated Kyntral principal is required");
  }
  return opaque(principal, "principalId");
}

function assertOwnsDevice(
  store: KyntralStore,
  principalId: string,
  deviceId: string
) {
  const device = store.getDevice(deviceId);
  if (!device || device.principalId !== principalId) {
    throw new Error("Unknown deviceId");
  }
  return device;
}

const executionReceiptSchema = z.object({
  version: z.literal("kyntral.receipt.v1"),
  receiptId: z.string().min(3).max(128),
  actionId: z.string().min(3).max(128),
  deviceId: z.string().min(3).max(128),
  actionHash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  outcome: z.enum(["completed", "partial", "failed", "cancelled"]),
  startedAt: z.string(),
  completedAt: z.string(),
  counts: z.object({
    completed: z.number().int().nonnegative(),
    failed: z.number().int().nonnegative()
  }),
  deviceProof: z.object({
    keyId: z.string().min(3).max(128),
    algorithm: z.literal("ES256"),
    signature: z.string().regex(/^[A-Za-z0-9_-]+$/)
  })
});

export function createKyntralServer(
  options: KyntralServerOptions
): McpServer {
  const store = options.store;
  const authorizationStore =
    options.authorizationStore ?? new PersistentAuthorizationStore(store);

  const server = new McpServer(
    {
      name: "kyntral",
      title: "Kyntral",
      version: "0.1.0-rc"
    },
    {
      capabilities: { tools: {} },
      instructions:
        "Kyntral mediates explicitly authorized work on paired devices. " +
        "AI proposal is not authorization; authorization is not execution; " +
        "execution is not verification. Never request private workflow payloads. " +
        "Treat completion as verified only after a device-signed receipt passes Kyntral verification."
    }
  );

  server.registerTool(
    "kyntral_get_profile",
    {
      title: "Get Kyntral profile",
      description:
        "Return the opaque Kyntral principal identifier for the authenticated connection.",
      inputSchema: z.object({}),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      scopeChallenge: requireScopes(KYNTRAL_SCOPES.read),
      _meta: {
        ...securityMeta([KYNTRAL_SCOPES.read]),
        "openai/profile": true
      }
    },
    async (_args, ctx) => textResult({
      id: requirePrincipal(ctx.http?.authInfo)
    })
  );

  server.registerTool(
    "kyntral_get_device",
    {
      title: "Get Kyntral device state",
      description:
        "Read minimal status for a paired device owned by the authenticated Kyntral principal.",
      inputSchema: z.object({ deviceId: z.string().min(3).max(128) }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      scopeChallenge: requireScopes(KYNTRAL_SCOPES.read),
      _meta: securityMeta([KYNTRAL_SCOPES.read])
    },
    async ({ deviceId }, ctx) => {
      const principalId = requirePrincipal(ctx.http?.authInfo);
      const id = opaque(deviceId, "deviceId");
      const device = assertOwnsDevice(store, principalId, id);
      return textResult({
        deviceId: id,
        state: device.revokedAt === null ? "paired" : "revoked",
        executionAuthority: "device",
        contentLocation: "device"
      });
    }
  );

  server.registerTool(
    "kyntral_list_capabilities",
    {
      title: "List Kyntral capabilities",
      description:
        "List capability identifiers supported by Kyntral. Support does not imply a grant.",
      inputSchema: z.object({ scopeId: z.string().min(3).max(128) }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      scopeChallenge: requireScopes(KYNTRAL_SCOPES.read),
      _meta: securityMeta([KYNTRAL_SCOPES.read])
    },
    async ({ scopeId }, ctx) => {
      requirePrincipal(ctx.http?.authInfo);
      return textResult({
        scopeId: opaque(scopeId, "scopeId"),
        supportedCapabilities: [
          { id: "workflow.preview", risk: "K0" },
          { id: "workflow.execute", risk: "K2" },
          { id: "receipt.read", risk: "K0" },
          { id: "receipt.submit", risk: "K1" }
        ]
      });
    }
  );

  server.registerTool(
    "kyntral_preview_workflow",
    {
      title: "Preview Kyntral workflow authorization",
      description:
        "Evaluate the exact principal/device/scope/workflow grant without requesting private workflow payloads.",
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
      },
      scopeChallenge: requireScopes(KYNTRAL_SCOPES.read),
      _meta: securityMeta([KYNTRAL_SCOPES.read])
    },
    async ({ deviceId, scopeId, workflowId }, ctx) => {
      const principalId = requirePrincipal(ctx.http?.authInfo);
      const query = {
        principalId,
        deviceId: opaque(deviceId, "deviceId"),
        scopeId: opaque(scopeId, "scopeId"),
        workflowId: opaque(workflowId, "workflowId"),
        capability: "workflow.execute",
        risk: "K2" as const
      };
      const decision = await authorizationStore.evaluate(query);
      return textResult({
        deviceId: query.deviceId,
        scopeId: query.scopeId,
        workflowId: query.workflowId,
        capability: query.capability,
        risk: query.risk,
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
        "Issue and persist one signed content-free ActionEnvelope only after the exact principal-bound grant evaluates to Allowed.",
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
      },
      scopeChallenge: requireScopes(KYNTRAL_SCOPES.execute),
      _meta: securityMeta([KYNTRAL_SCOPES.execute])
    },
    async ({ deviceId, scopeId, workflowId }, ctx) => {
      const principalId = requirePrincipal(ctx.http?.authInfo);
      const query = {
        principalId,
        deviceId: opaque(deviceId, "deviceId"),
        scopeId: opaque(scopeId, "scopeId"),
        workflowId: opaque(workflowId, "workflowId"),
        capability: "workflow.execute",
        risk: "K2" as const
      };
      const decision = await authorizationStore.evaluate(query);
      requireAllowed(decision);

      const actionId = "act_" + randomUUID().replaceAll("-", "");
      const issued = issueSignedAction({
        actionId,
        query,
        signer: options.actionSigner
      });
      const job = createCloudJob({
        actionId,
        deviceId: query.deviceId,
        scopeId: query.scopeId,
        workflowId: query.workflowId,
        capability: query.capability,
        risk: query.risk,
        expiresAt: issued.action.expiresAt
      });
      store.putAuthorizedJob(job, issued);
      return textResult({
        job,
        action: issued.action
      });
    }
  );

  server.registerTool(
    "kyntral_get_job",
    {
      title: "Get Kyntral job",
      description: "Read content-free state for an action owned by the authenticated principal.",
      inputSchema: z.object({ actionId: z.string().min(3).max(128) }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      scopeChallenge: requireScopes(KYNTRAL_SCOPES.read),
      _meta: securityMeta([KYNTRAL_SCOPES.read])
    },
    async ({ actionId }, ctx) => {
      const principalId = requirePrincipal(ctx.http?.authInfo);
      const id = opaque(actionId, "actionId");
      const job = store.getJob(id);
      if (!job) throw new Error("Unknown actionId");
      assertOwnsDevice(store, principalId, job.deviceId);
      return textResult(job);
    }
  );

  server.registerTool(
    "kyntral_cancel_job",
    {
      title: "Cancel Kyntral job",
      description:
        "Cancel a known queued action owned by the authenticated principal. This does not broaden any grant.",
      inputSchema: z.object({ actionId: z.string().min(3).max(128) }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      scopeChallenge: requireScopes(KYNTRAL_SCOPES.execute),
      _meta: securityMeta([KYNTRAL_SCOPES.execute])
    },
    async ({ actionId }, ctx) => {
      const principalId = requirePrincipal(ctx.http?.authInfo);
      const id = opaque(actionId, "actionId");
      const job = store.getJob(id);
      if (!job) throw new Error("Unknown actionId");
      assertOwnsDevice(store, principalId, job.deviceId);
      const cancelled = store.updateJobState(id, "cancelled");
      if (!cancelled) throw new Error("Unknown actionId");
      return textResult(cancelled);
    }
  );

  server.registerTool(
    "kyntral_submit_receipt",
    {
      title: "Submit signed Kyntral execution receipt",
      description:
        "Submit a content-free device-signed receipt. Kyntral verifies the exact stored ActionEnvelope, device identity, authorization signature, timing, and receipt binding before updating job state.",
      inputSchema: z.object({ receipt: executionReceiptSchema }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      scopeChallenge: requireScopes(KYNTRAL_SCOPES.receiptSubmit),
      _meta: securityMeta([KYNTRAL_SCOPES.receiptSubmit])
    },
    async ({ receipt }, ctx) => {
      const principalId = requirePrincipal(ctx.http?.authInfo);
      const result = verifyAndStoreReceipt({
        store,
        principalId,
        receipt: receipt as ExecutionReceipt
      });
      return textResult({
        status: result.status,
        verified: true,
        receipt: result.receipt
      });
    }
  );

  server.registerTool(
    "kyntral_get_receipt",
    {
      title: "Get Kyntral execution receipt",
      description:
        "Read a content-free receipt that has already passed Kyntral cryptographic verification for an action owned by the authenticated principal.",
      inputSchema: z.object({ actionId: z.string().min(3).max(128) }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      scopeChallenge: requireScopes(KYNTRAL_SCOPES.read),
      _meta: securityMeta([KYNTRAL_SCOPES.read])
    },
    async ({ actionId }, ctx) => {
      const principalId = requirePrincipal(ctx.http?.authInfo);
      const id = opaque(actionId, "actionId");
      const job = store.getJob(id);
      if (!job) throw new Error("Unknown actionId");
      assertOwnsDevice(store, principalId, job.deviceId);
      const receipt = store.getReceipt(id);
      if (!receipt) throw new Error("Receipt not available");
      return textResult(receipt);
    }
  );

  server.registerTool(
    "kyntral_create_pairing_challenge",
    {
      title: "Create device pairing challenge",
      description:
        "Create a one-time five-minute challenge for pairing a device to the authenticated principal.",
      inputSchema: z.object({}),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      },
      scopeChallenge: requireScopes(KYNTRAL_SCOPES.pair),
      _meta: securityMeta([KYNTRAL_SCOPES.pair])
    },
    async (_args, ctx) => {
      const principalId = requirePrincipal(ctx.http?.authInfo);
      return textResult(createPairingChallenge(store, principalId));
    }
  );

  server.registerTool(
    "kyntral_complete_pairing",
    {
      title: "Complete device pairing",
      description:
        "Verify a device-signed one-time pairing proof and register only its public device identities.",
      inputSchema: z.object({
        proof: z.object({
          version: z.literal("kyntral.pairing-proof.v1"),
          challengeId: z.string(),
          nonce: z.string(),
          deviceIdentity: z.object({
            version: z.literal("kyntral.device.v1"),
            deviceId: z.string(),
            platform: z.literal("ios"),
            signingPublicKey: z.object({
              kty: z.literal("EC"),
              crv: z.literal("P-256"),
              x: z.string(),
              y: z.string(),
              kid: z.string(),
              use: z.literal("sig"),
              alg: z.literal("ES256")
            }),
            keyAgreementPublicKey: z.object({
              kty: z.literal("EC"),
              crv: z.literal("P-256"),
              x: z.string(),
              y: z.string(),
              kid: z.string(),
              use: z.literal("enc"),
              alg: z.literal("ECDH-ES")
            }),
            createdAt: z.string(),
            revokedAt: z.string().optional()
          }),
          proof: z.object({
            keyId: z.string(),
            algorithm: z.literal("ES256"),
            signature: z.string()
          })
        })
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      },
      scopeChallenge: requireScopes(KYNTRAL_SCOPES.pair),
      _meta: securityMeta([KYNTRAL_SCOPES.pair])
    },
    async ({ proof }, ctx) => {
      const principalId = requirePrincipal(ctx.http?.authInfo);
      const identity = verifyAndConsumePairingProof({
        store,
        principalId,
        proof: proof as PairingProof
      });
      return textResult({
        deviceId: identity.deviceId,
        state: "paired",
        signingKeyId: identity.signingPublicKey.kid,
        keyAgreementKeyId: identity.keyAgreementPublicKey.kid
      });
    }
  );

  server.registerTool(
    "kyntral_revoke_device",
    {
      title: "Revoke paired device",
      description:
        "Revoke an authenticated principal's paired device. Future authorization decisions and receipt verification for it fail as Revoked.",
      inputSchema: z.object({ deviceId: z.string().min(3).max(128) }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: false
      },
      scopeChallenge: requireScopes(KYNTRAL_SCOPES.revoke),
      _meta: securityMeta([KYNTRAL_SCOPES.revoke])
    },
    async ({ deviceId }, ctx) => {
      const principalId = requirePrincipal(ctx.http?.authInfo);
      const id = opaque(deviceId, "deviceId");
      assertOwnsDevice(store, principalId, id);
      const changed = store.revokeDevice(id);
      return textResult({
        deviceId: id,
        state: "revoked",
        changed
      });
    }
  );

  return server;
}

// SPDX-License-Identifier: BUSL-1.1

import {
  createMcpHandler,
  getOAuthProtectedResourceMetadataUrl,
  requireBearerAuth,
  type AuthInfo
} from "@modelcontextprotocol/server";
import {
  Es256ActionSigner,
  type P256PrivateJwk
} from "./action.js";
import type { ExecutionReceipt } from "./crypto.js";
import {
  DEVICE_REQUEST_PROOF_HEADER,
  decodeDeviceRequestHeader,
  verifyAndConsumeDeviceRequest
} from "./device-request.js";
import { assertOpaqueId } from "./domain.js";
import { IntrospectionTokenVerifier } from "./oauth.js";
import {
  createPairingChallenge,
  verifyAndConsumePairingProof,
  type PairingProof
} from "./pairing.js";
import { verifyAndStoreReceipt } from "./receipt.js";
import { KYNTRAL_SCOPES, createKyntralServer } from "./server.js";
import { SqliteKyntralStore, type KyntralStore } from "./store.js";

export type KyntralHttpConfig = Readonly<{
  publicMcpUrl: URL;
  oauthIssuer: URL;
  oauthIntrospectionUrl: URL;
  oauthClientId: string;
  oauthClientSecret: string;
  deviceOAuthClientId: string;
  actionSigner: Es256ActionSigner;
  databasePath: string;
  oauthFetch?: typeof fetch;
  store?: KyntralStore;
  now?: () => Date;
}>;

const MAX_DEVICE_REQUEST_BYTES = 64 * 1024;

function requireProductionHttps(url: URL, field: string): void {
  if (url.protocol !== "https:") {
    throw new Error(field + " must use HTTPS");
  }
}

function decodeActionSigningKey(value: string): P256PrivateJwk {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
  } catch {
    throw new Error("KYNTRAL_ACTION_SIGNING_PRIVATE_JWK_B64 must be base64url JSON");
  }
  if (!parsed || typeof parsed !== "object") {
    throw new Error("KYNTRAL_ACTION_SIGNING_PRIVATE_JWK_B64 must contain a JWK object");
  }
  return parsed as P256PrivateJwk;
}

function principalId(authInfo: AuthInfo): string {
  const principal = authInfo.extra?.kyntralPrincipalId;
  if (typeof principal !== "string") {
    throw new Error("Authenticated Kyntral principal is required");
  }
  return assertOpaqueId(principal, "principalId");
}

function requireHttpScope(
  authInfo: AuthInfo,
  scope: string,
  resourceMetadataUrl: string
): Response | null {
  if (authInfo.scopes.includes(scope)) return null;

  return Response.json(
    { error: "insufficient_scope" },
    {
      status: 403,
      headers: {
        "www-authenticate":
          `Bearer error="insufficient_scope", scope="${scope}", ` +
          `resource_metadata="${resourceMetadataUrl}"`
      }
    }
  );
}

async function readBoundedBody(request: Request): Promise<Uint8Array> {
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > MAX_DEVICE_REQUEST_BYTES) {
    throw new Error("request too large");
  }

  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > MAX_DEVICE_REQUEST_BYTES) {
    throw new Error("request too large");
  }
  return bytes;
}

async function readBoundedJson<T>(request: Request): Promise<T> {
  const bytes = await readBoundedBody(request);
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

function verifyDevicePossession(input: {
  request: Request;
  store: KyntralStore;
  deviceId: string;
  method: "GET" | "POST";
  path: string;
  body: Uint8Array;
  now: Date;
}): void {
  const header = input.request.headers.get(DEVICE_REQUEST_PROOF_HEADER);
  if (!header) throw new Error("missing device request proof");
  verifyAndConsumeDeviceRequest({
    store: input.store,
    proof: decodeDeviceRequestHeader(header),
    expectedDeviceId: input.deviceId,
    method: input.method,
    path: input.path,
    body: input.body,
    now: input.now
  });
}

function deviceIdFromPath(pathname: string): string | null {
  const match = /^\/v1\/devices\/([^/]+)$/.exec(pathname);
  if (!match) return null;
  try {
    return assertOpaqueId(decodeURIComponent(match[1]!), "deviceId");
  } catch {
    return null;
  }
}

function revokedDeviceIdFromPath(pathname: string): string | null {
  const match = /^\/v1\/devices\/([^/]+)\/revoke$/.exec(pathname);
  if (!match) return null;
  try {
    return assertOpaqueId(decodeURIComponent(match[1]!), "deviceId");
  } catch {
    return null;
  }
}

function actionDeviceIdFromPath(pathname: string): string | null {
  const match = /^\/v1\/devices\/([^/]+)\/actions\/next$/.exec(pathname);
  if (!match) return null;
  try {
    return assertOpaqueId(decodeURIComponent(match[1]!), "deviceId");
  } catch {
    return null;
  }
}

function receiptDeviceIdFromPath(pathname: string): string | null {
  const match = /^\/v1\/devices\/([^/]+)\/receipts$/.exec(pathname);
  if (!match) return null;
  try {
    return assertOpaqueId(decodeURIComponent(match[1]!), "deviceId");
  } catch {
    return null;
  }
}

export function loadHttpConfig(
  env: NodeJS.ProcessEnv = process.env
): KyntralHttpConfig {
  const required = [
    "KYNTRAL_PUBLIC_MCP_URL",
    "KYNTRAL_OAUTH_ISSUER",
    "KYNTRAL_OAUTH_INTROSPECTION_URL",
    "KYNTRAL_OAUTH_CLIENT_ID",
    "KYNTRAL_OAUTH_CLIENT_SECRET",
    "KYNTRAL_DEVICE_OAUTH_CLIENT_ID",
    "KYNTRAL_ACTION_SIGNING_PRIVATE_JWK_B64"
  ] as const;

  for (const name of required) {
    if (!env[name]) throw new Error("Missing required environment variable: " + name);
  }

  const publicMcpUrl = new URL(env.KYNTRAL_PUBLIC_MCP_URL!);
  const oauthIssuer = new URL(env.KYNTRAL_OAUTH_ISSUER!);
  const oauthIntrospectionUrl = new URL(env.KYNTRAL_OAUTH_INTROSPECTION_URL!);

  requireProductionHttps(publicMcpUrl, "KYNTRAL_PUBLIC_MCP_URL");
  requireProductionHttps(oauthIssuer, "KYNTRAL_OAUTH_ISSUER");
  requireProductionHttps(oauthIntrospectionUrl, "KYNTRAL_OAUTH_INTROSPECTION_URL");

  if (publicMcpUrl.pathname !== "/mcp") {
    throw new Error("KYNTRAL_PUBLIC_MCP_URL must end at /mcp");
  }

  return {
    publicMcpUrl,
    oauthIssuer,
    oauthIntrospectionUrl,
    oauthClientId: env.KYNTRAL_OAUTH_CLIENT_ID!,
    oauthClientSecret: env.KYNTRAL_OAUTH_CLIENT_SECRET!,
    deviceOAuthClientId: env.KYNTRAL_DEVICE_OAUTH_CLIENT_ID!,
    actionSigner: new Es256ActionSigner(
      decodeActionSigningKey(env.KYNTRAL_ACTION_SIGNING_PRIVATE_JWK_B64!)
    ),
    databasePath: env.KYNTRAL_DB_PATH ?? "./data/kyntral.db"
  };
}

export function createKyntralHttpHandler(config: KyntralHttpConfig) {
  const store = config.store ?? new SqliteKyntralStore(config.databasePath);
  const now = config.now ?? (() => new Date());
  const mcpHandler = createMcpHandler(() =>
    createKyntralServer({
      store,
      actionSigner: config.actionSigner
    })
  );
  const resourceMetadataUrl =
    getOAuthProtectedResourceMetadataUrl(config.publicMcpUrl);

  const verifierOptions = {
    issuer: config.oauthIssuer,
    introspectionUrl: config.oauthIntrospectionUrl,
    clientId: config.oauthClientId,
    clientSecret: config.oauthClientSecret,
    expectedResource: config.publicMcpUrl,
    ...(config.oauthFetch ? { fetchFn: config.oauthFetch } : {})
  };

  const gate = requireBearerAuth({
    verifier: new IntrospectionTokenVerifier(verifierOptions),
    expectedResource: config.publicMcpUrl,
    requiredScopes: [],
    resourceMetadataUrl
  });

  const protectedResourceMetadata = {
    resource: config.publicMcpUrl.href,
    authorization_servers: [config.oauthIssuer.href],
    scopes_supported: Object.values(KYNTRAL_SCOPES),
    bearer_methods_supported: ["header"]
  };

  async function authenticated(request: Request): Promise<AuthInfo | Response> {
    return gate(request);
  }

  function requireDeviceOAuthClient(authInfo: AuthInfo): Response | null {
    if (authInfo.clientId === config.deviceOAuthClientId) return null;
    return Response.json(
      { error: "device_client_required" },
      { status: 403 }
    );
  }

  return async function handleRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.href === resourceMetadataUrl) {
      if (request.method !== "GET") {
        return new Response(null, {
          status: 405,
          headers: { allow: "GET" }
        });
      }
      return Response.json(protectedResourceMetadata, {
        headers: {
          "cache-control": "public, max-age=300",
          "access-control-allow-origin": "*"
        }
      });
    }

    if (url.pathname === "/healthz") {
      return Response.json({
        status: "ok",
        service: "kyntral-mcp",
        version: "0.1.0-rc"
      });
    }

    if (url.pathname === "/v1/pairing/challenge") {
      if (request.method !== "POST") {
        return new Response(null, { status: 405, headers: { allow: "POST" } });
      }
      const authInfo = await authenticated(request);
      if (authInfo instanceof Response) return authInfo;
      const scopeError = requireHttpScope(
        authInfo,
        KYNTRAL_SCOPES.pair,
        resourceMetadataUrl
      );
      if (scopeError) return scopeError;
      const clientError = requireDeviceOAuthClient(authInfo);
      if (clientError) return clientError;

      return Response.json(
        createPairingChallenge(store, principalId(authInfo)),
        { status: 201 }
      );
    }

    if (url.pathname === "/v1/pairing/complete") {
      if (request.method !== "POST") {
        return new Response(null, { status: 405, headers: { allow: "POST" } });
      }
      const authInfo = await authenticated(request);
      if (authInfo instanceof Response) return authInfo;
      const scopeError = requireHttpScope(
        authInfo,
        KYNTRAL_SCOPES.pair,
        resourceMetadataUrl
      );
      if (scopeError) return scopeError;
      const clientError = requireDeviceOAuthClient(authInfo);
      if (clientError) return clientError;

      try {
        const proof = await readBoundedJson<PairingProof>(request);
        const identity = verifyAndConsumePairingProof({
          store,
          principalId: principalId(authInfo),
          proof
        });
        return Response.json({
          deviceId: identity.deviceId,
          state: "paired",
          signingKeyId: identity.signingPublicKey.kid,
          keyAgreementKeyId: identity.keyAgreementPublicKey.kid,
          authorizationSigningKey: config.actionSigner.publicKey
        });
      } catch {
        return Response.json(
          { error: "invalid_pairing_proof" },
          { status: 400 }
        );
      }
    }

    const actionDeviceId = actionDeviceIdFromPath(url.pathname);
    if (actionDeviceId !== null) {
      if (request.method !== "GET") {
        return new Response(null, { status: 405, headers: { allow: "GET" } });
      }
      const authInfo = await authenticated(request);
      if (authInfo instanceof Response) return authInfo;
      const scopeError = requireHttpScope(
        authInfo,
        KYNTRAL_SCOPES.deviceExecute,
        resourceMetadataUrl
      );
      if (scopeError) return scopeError;
      const clientError = requireDeviceOAuthClient(authInfo);
      if (clientError) return clientError;

      const device = store.getDevice(actionDeviceId);
      if (!device || device.principalId !== principalId(authInfo)) {
        return Response.json({ error: "device_not_found" }, { status: 404 });
      }
      if (device.revokedAt !== null) {
        return Response.json({ error: "device_revoked" }, { status: 403 });
      }

      try {
        verifyDevicePossession({
          request,
          store,
          deviceId: actionDeviceId,
          method: "GET",
          path: url.pathname,
          body: new Uint8Array(),
          now: now()
        });
      } catch {
        return Response.json(
          { error: "invalid_device_request_proof" },
          { status: 401 }
        );
      }

      const delivery = store.claimNextAction(actionDeviceId, now());
      if (!delivery) return new Response(null, { status: 204 });

      return Response.json({
        action: delivery.signedAction.action
      }, {
        headers: {
          "cache-control": "no-store"
        }
      });
    }

    const receiptDeviceId = receiptDeviceIdFromPath(url.pathname);
    if (receiptDeviceId !== null) {
      if (request.method !== "POST") {
        return new Response(null, { status: 405, headers: { allow: "POST" } });
      }
      const authInfo = await authenticated(request);
      if (authInfo instanceof Response) return authInfo;
      const scopeError = requireHttpScope(
        authInfo,
        KYNTRAL_SCOPES.receiptSubmit,
        resourceMetadataUrl
      );
      if (scopeError) return scopeError;
      const clientError = requireDeviceOAuthClient(authInfo);
      if (clientError) return clientError;

      const device = store.getDevice(receiptDeviceId);
      if (!device || device.principalId !== principalId(authInfo)) {
        return Response.json({ error: "device_not_found" }, { status: 404 });
      }

      try {
        const body = await readBoundedBody(request);
        verifyDevicePossession({
          request,
          store,
          deviceId: receiptDeviceId,
          method: "POST",
          path: url.pathname,
          body,
          now: now()
        });
        const receipt = JSON.parse(
          new TextDecoder().decode(body)
        ) as ExecutionReceipt;
        if (receipt.deviceId !== receiptDeviceId) {
          throw new Error("receipt device mismatch");
        }
        const result = verifyAndStoreReceipt({
          store,
          principalId: principalId(authInfo),
          receipt,
          now: now()
        });
        return Response.json({
          status: result.status,
          verified: true,
          receipt: result.receipt
        }, {
          status: result.status === "accepted" ? 201 : 200,
          headers: {
            "cache-control": "no-store"
          }
        });
      } catch {
        return Response.json(
          { error: "receipt_not_accepted" },
          { status: 400 }
        );
      }
    }

    const deviceId = deviceIdFromPath(url.pathname);
    if (deviceId !== null) {
      if (request.method !== "GET") {
        return new Response(null, { status: 405, headers: { allow: "GET" } });
      }
      const authInfo = await authenticated(request);
      if (authInfo instanceof Response) return authInfo;
      const scopeError = requireHttpScope(
        authInfo,
        KYNTRAL_SCOPES.read,
        resourceMetadataUrl
      );
      if (scopeError) return scopeError;
      const clientError = requireDeviceOAuthClient(authInfo);
      if (clientError) return clientError;

      const device = store.getDevice(deviceId);
      if (!device || device.principalId !== principalId(authInfo)) {
        return Response.json({ error: "device_not_found" }, { status: 404 });
      }
      return Response.json({
        deviceId,
        state: device.revokedAt === null ? "paired" : "revoked",
        executionAuthority: "device",
        contentLocation: "device"
      });
    }

    const revokeDeviceId = revokedDeviceIdFromPath(url.pathname);
    if (revokeDeviceId !== null) {
      if (request.method !== "POST") {
        return new Response(null, { status: 405, headers: { allow: "POST" } });
      }
      const authInfo = await authenticated(request);
      if (authInfo instanceof Response) return authInfo;
      const scopeError = requireHttpScope(
        authInfo,
        KYNTRAL_SCOPES.revoke,
        resourceMetadataUrl
      );
      if (scopeError) return scopeError;
      const clientError = requireDeviceOAuthClient(authInfo);
      if (clientError) return clientError;

      const device = store.getDevice(revokeDeviceId);
      if (!device || device.principalId !== principalId(authInfo)) {
        return Response.json({ error: "device_not_found" }, { status: 404 });
      }
      const changed = store.revokeDevice(revokeDeviceId);
      return Response.json({
        deviceId: revokeDeviceId,
        state: "revoked",
        changed
      });
    }

    if (url.pathname !== "/mcp") {
      return new Response("Not Found", { status: 404 });
    }

    const authInfo = await authenticated(request);
    if (authInfo instanceof Response) return authInfo;

    return mcpHandler.fetch(request, { authInfo });
  };
}

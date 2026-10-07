// SPDX-License-Identifier: BUSL-1.1

import { readFileSync } from "node:fs";
import {
  generateKeyPairSync,
  type JsonWebKey
} from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  Es256ActionSigner,
  type P256PrivateJwk
} from "../src/action.js";
import type {
  ExecutionReceipt,
  P256PublicJwk,
  SignedActionEnvelope
} from "../src/crypto.js";
import { createCloudJob } from "../src/domain.js";
import { deriveOpaquePrincipalId } from "../src/oauth.js";
import { KYNTRAL_SCOPES } from "../src/server.js";
import { SqliteKyntralStore } from "../src/store.js";
import {
  createKyntralHttpHandler,
  loadHttpConfig,
  type KyntralHttpConfig
} from "../src/http.js";

const resource = new URL("https://api.example.test/mcp");
const issuer = new URL("https://identity.example.test/");

const vectors = JSON.parse(
  readFileSync(
    new URL("../../protocol/test-vectors/crypto-v1.json", import.meta.url),
    "utf8"
  )
) as {
  authorizationPublicKeyJwk: P256PublicJwk;
  signedAction: SignedActionEnvelope;
  actionHash: string;
  deviceSigningPublicKeyJwk: P256PublicJwk;
  deviceKeyAgreementPublicKeyJwk: P256PublicJwk;
  signedReceipt: ExecutionReceipt;
};

function pairedStore(
  revokedAt: string | null = null
): SqliteKyntralStore {
  const store = new SqliteKyntralStore(":memory:");
  const principalId = deriveOpaquePrincipalId(
    issuer,
    "device-owner-123"
  );
  store.putDevice({
    deviceId: vectors.signedAction.deviceId,
    principalId,
    identityJson: JSON.stringify({
      version: "kyntral.device.v1",
      deviceId: vectors.signedAction.deviceId,
      platform: "ios",
      signingPublicKey: vectors.deviceSigningPublicKeyJwk,
      keyAgreementPublicKey: vectors.deviceKeyAgreementPublicKeyJwk,
      createdAt: "2026-10-06T22:00:00.000Z"
    }),
    createdAt: "2026-10-06T22:00:00.000Z",
    revokedAt
  });
  const action = vectors.signedAction;
  const job = createCloudJob({
    actionId: action.actionId,
    deviceId: action.deviceId,
    scopeId: action.scopeId,
    workflowId: action.workflowId,
    capability: action.capability,
    risk: action.risk,
    expiresAt: action.expiresAt
  });
  store.putAuthorizedJob(job, {
    action,
    authorizationKey: vectors.authorizationPublicKeyJwk,
    actionHash: vectors.actionHash
  }, new Date("2026-10-06T23:00:00.000Z"));
  return store;
}

function signingJwk(kid = "auth_http_001"): P256PrivateJwk {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.privateKey.export({ format: "jwk" }) as JsonWebKey;
  return {
    kty: "EC",
    crv: "P-256",
    x: String(jwk.x),
    y: String(jwk.y),
    d: String(jwk.d),
    kid,
    use: "sig",
    alg: "ES256"
  };
}

function signingKeyB64(): string {
  return Buffer.from(JSON.stringify(signingJwk()), "utf8").toString("base64url");
}

function configForScopes(scopes: string[]): KyntralHttpConfig {
  const oauthFetch = vi.fn(async () =>
    Response.json({
      active: true,
      client_id: "ios-client",
      scope: scopes.join(" "),
      exp: Math.floor(Date.now() / 1000) + 300,
      sub: "device-owner-123",
      aud: resource.href,
      iss: issuer.href
    })
  ) as unknown as typeof fetch;

  return {
    publicMcpUrl: resource,
    oauthIssuer: issuer,
    oauthIntrospectionUrl: new URL("https://identity.example.test/introspect"),
    oauthClientId: "resource-server",
    oauthClientSecret: "test-secret",
    deviceOAuthClientId: "ios-client",
    actionSigner: new Es256ActionSigner(signingJwk()),
    databasePath: ":memory:",
    oauthFetch
  };
}

function request(path: string, init: RequestInit = {}): Request {
  return new Request(new URL(path, "https://api.example.test"), {
    ...init,
    headers: {
      authorization: "Bearer test-token",
      ...(init.headers ?? {})
    }
  });
}

function productionEnv(): NodeJS.ProcessEnv {
  return {
    KYNTRAL_PUBLIC_MCP_URL: resource.href,
    KYNTRAL_OAUTH_ISSUER: issuer.href,
    KYNTRAL_OAUTH_INTROSPECTION_URL: "https://identity.example.test/introspect",
    KYNTRAL_OAUTH_CLIENT_ID: "resource-server",
    KYNTRAL_OAUTH_CLIENT_SECRET: "test-secret",
    KYNTRAL_DEVICE_OAUTH_CLIENT_ID: "ios-client",
    KYNTRAL_ACTION_SIGNING_PRIVATE_JWK_B64: signingKeyB64(),
    KYNTRAL_DB_PATH: ":memory:"
  };
}

describe("production HTTP configuration", () => {
  it("fails closed when the action signing key is missing", () => {
    const env = productionEnv();
    delete env.KYNTRAL_ACTION_SIGNING_PRIVATE_JWK_B64;
    expect(() => loadHttpConfig(env)).toThrow(
      /KYNTRAL_ACTION_SIGNING_PRIVATE_JWK_B64/
    );
  });

  it("loads the ES256 action signer from base64url JWK configuration", () => {
    const config = loadHttpConfig(productionEnv());
    expect(config.actionSigner.publicKey.kid).toBe("auth_http_001");
    expect(config.actionSigner.publicKey.alg).toBe("ES256");
  });
});

describe("OAuth-bound device HTTP surface", () => {
  it("creates a content-free one-time pairing challenge with pair scope", async () => {
    const handler = createKyntralHttpHandler(
      configForScopes(["kyntral.pair"])
    );

    const response = await handler(request("/v1/pairing/challenge", {
      method: "POST"
    }));
    expect(response.status).toBe(201);

    const body = await response.json() as Record<string, unknown>;
    expect(body.version).toBe("kyntral.pairing-challenge.v1");
    expect(String(body.challengeId)).toMatch(/^pair_[A-Za-z0-9_-]+$/);
    expect(String(body.principalId)).toMatch(/^usr_[A-Za-z0-9_-]+$/);
    expect(String(body.nonce)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(JSON.stringify(body)).not.toContain("device-owner-123");
  });

  it("rejects device HTTP access from a non-iOS OAuth client", async () => {
    const base = configForScopes(["kyntral.pair"]);
    const foreignFetch = vi.fn(async () =>
      Response.json({
        active: true,
        client_id: "openai-client",
        scope: "kyntral.pair",
        exp: Math.floor(Date.now() / 1000) + 300,
        sub: "device-owner-123",
        aud: resource.href,
        iss: issuer.href
      })
    ) as unknown as typeof fetch;
    const handler = createKyntralHttpHandler({
      ...base,
      oauthFetch: foreignFetch
    });

    const response = await handler(request("/v1/pairing/challenge", {
      method: "POST"
    }));
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({
      error: "device_client_required"
    });
  });

  it("rejects pairing when the bearer token lacks kyntral.pair", async () => {
    const handler = createKyntralHttpHandler(
      configForScopes(["kyntral.read"])
    );

    const response = await handler(request("/v1/pairing/challenge", {
      method: "POST"
    }));
    expect(response.status).toBe(403);
    expect(response.headers.get("www-authenticate")).toContain("kyntral.pair");
  });

  it("does not enumerate devices owned by another or unknown principal", async () => {
    const handler = createKyntralHttpHandler(
      configForScopes(["kyntral.read"])
    );

    const response = await handler(request("/v1/devices/dev_unknown_001"));
    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toEqual({ error: "device_not_found" });
  });

  it("bounds pairing proof request bodies before verification", async () => {
    const handler = createKyntralHttpHandler(
      configForScopes(["kyntral.pair"])
    );
    const oversized = "x".repeat(70 * 1024);

    const response = await handler(request("/v1/pairing/complete", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ oversized })
    }));
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "invalid_pairing_proof"
    });
  });
});


describe("device action delivery HTTP surface", () => {
  it("requires the dedicated device execution scope", async () => {
    const store = pairedStore();
    const handler = createKyntralHttpHandler({
      ...configForScopes([KYNTRAL_SCOPES.read]),
      store,
      now: () => new Date("2026-10-06T23:01:00.000Z")
    });

    const response = await handler(request(
      "/v1/devices/" + vectors.signedAction.deviceId + "/actions/next"
    ));
    expect(response.status).toBe(403);
    expect(response.headers.get("www-authenticate"))
      .toContain(KYNTRAL_SCOPES.deviceExecute);
    store.close();
  });

  it("delivers only the exact device action and resumes the same in-flight action", async () => {
    const store = pairedStore();
    const handler = createKyntralHttpHandler({
      ...configForScopes([KYNTRAL_SCOPES.deviceExecute]),
      store,
      now: () => new Date("2026-10-06T23:01:00.000Z")
    });
    const path =
      "/v1/devices/" + vectors.signedAction.deviceId + "/actions/next";

    const first = await handler(request(path));
    expect(first.status).toBe(200);
    const firstBody = await first.json() as {
      action: SignedActionEnvelope;
    };
    expect(firstBody.action).toEqual(vectors.signedAction);
    expect(store.getJob(vectors.signedAction.actionId)?.state)
      .toBe("executing");

    const resumed = await handler(request(path));
    expect(resumed.status).toBe(200);
    const resumedBody = await resumed.json() as {
      action: SignedActionEnvelope;
    };
    expect(resumedBody.action.actionId)
      .toBe(vectors.signedAction.actionId);
    store.close();
  });

  it("does not deliver work to an unknown or revoked device", async () => {
    const store = pairedStore();
    const handler = createKyntralHttpHandler({
      ...configForScopes([KYNTRAL_SCOPES.deviceExecute]),
      store,
      now: () => new Date("2026-10-06T23:01:00.000Z")
    });
    const unknown = await handler(request(
      "/v1/devices/dev_unknown_001/actions/next"
    ));
    expect(unknown.status).toBe(404);
    store.close();

    const revoked = pairedStore("2026-10-06T23:00:30.000Z");
    const revokedHandler = createKyntralHttpHandler({
      ...configForScopes([KYNTRAL_SCOPES.deviceExecute]),
      store: revoked,
      now: () => new Date("2026-10-06T23:01:00.000Z")
    });
    const denied = await revokedHandler(request(
      "/v1/devices/" + vectors.signedAction.deviceId + "/actions/next"
    ));
    expect(denied.status).toBe(403);
    revoked.close();
  });
});

describe("device receipt HTTP surface", () => {
  it("requires receipt scope and finalizes only after exact verified receipt", async () => {
    const deniedStore = pairedStore();
    const deniedHandler = createKyntralHttpHandler({
      ...configForScopes([KYNTRAL_SCOPES.deviceExecute]),
      store: deniedStore,
      now: () => new Date("2026-10-06T23:01:00.000Z")
    });
    const receiptPath =
      "/v1/devices/" + vectors.signedAction.deviceId + "/receipts";
    const denied = await deniedHandler(request(receiptPath, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(vectors.signedReceipt)
    }));
    expect(denied.status).toBe(403);
    deniedStore.close();

    const store = pairedStore();
    const handler = createKyntralHttpHandler({
      ...configForScopes([KYNTRAL_SCOPES.receiptSubmit]),
      store,
      now: () => new Date("2026-10-06T23:01:00.000Z")
    });
    const accepted = await handler(request(receiptPath, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(vectors.signedReceipt)
    }));
    expect(accepted.status).toBe(201);
    const body = await accepted.json() as {
      status: string;
      verified: boolean;
    };
    expect(body).toMatchObject({
      status: "accepted",
      verified: true
    });
    expect(store.getJob(vectors.signedAction.actionId)?.state)
      .toBe("completed");
    store.close();
  });

  it("rejects a receipt when the URL device and signed receipt device differ", async () => {
    const store = pairedStore();
    const principalId = deriveOpaquePrincipalId(
      issuer,
      "device-owner-123"
    );
    store.putDevice({
      deviceId: "dev_other_001",
      principalId,
      identityJson: JSON.stringify({
        version: "kyntral.device.v1",
        deviceId: "dev_other_001",
        platform: "ios",
        signingPublicKey: vectors.deviceSigningPublicKeyJwk,
        keyAgreementPublicKey: vectors.deviceKeyAgreementPublicKeyJwk,
        createdAt: "2026-10-06T22:00:00.000Z"
      }),
      createdAt: "2026-10-06T22:00:00.000Z",
      revokedAt: null
    });
    const handler = createKyntralHttpHandler({
      ...configForScopes([KYNTRAL_SCOPES.receiptSubmit]),
      store,
      now: () => new Date("2026-10-06T23:01:00.000Z")
    });

    const response = await handler(request(
      "/v1/devices/dev_other_001/receipts",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(vectors.signedReceipt)
      }
    ));
    expect(response.status).toBe(400);
    expect(store.getJob(vectors.signedAction.actionId)?.state)
      .toBe("queued");
    store.close();
  });
});

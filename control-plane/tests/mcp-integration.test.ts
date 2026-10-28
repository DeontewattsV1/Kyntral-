// SPDX-License-Identifier: BUSL-1.1
// Regression coverage of the real SDK 2.4.0 /mcp HTTP boundary.
import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Es256ActionSigner, type P256PrivateJwk } from "../src/action.js";
import { createKyntralHttpHandler, type KyntralHttpConfig } from "../src/http.js";
import { deriveOpaquePrincipalId } from "../src/oauth.js";
import { KYNTRAL_SCOPES } from "../src/server.js";
import { SqliteKyntralStore } from "../src/store.js";

const resource = new URL("https://api.example.test/mcp");
const issuer = new URL("https://identity.example.test/");
const stores: SqliteKyntralStore[] = [];
afterEach(() => { for (const store of stores.splice(0)) store.close(); });

function config(scopes: string[], active = true, expiresIn = 300): KyntralHttpConfig {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.privateKey.export({ format: "jwk" }) as JsonWebKey;
  const actionSigner = new Es256ActionSigner({
    kty: "EC", crv: "P-256", x: String(jwk.x), y: String(jwk.y),
    d: String(jwk.d), kid: "mcp_test_signer", use: "sig", alg: "ES256"
  } satisfies P256PrivateJwk);
  const store = new SqliteKyntralStore(":memory:");
  stores.push(store);
  return {
    publicMcpUrl: resource,
    oauthIssuer: issuer,
    oauthIntrospectionUrl: new URL("https://identity.example.test/introspect"),
    oauthClientId: "resource-server",
    oauthClientSecret: "test-only-secret",
    deviceOAuthClientId: "ios-client",
    actionSigner, databasePath: ":memory:", store,
    oauthFetch: vi.fn(async () => Response.json({
      active, client_id: "test-client", scope: scopes.join(" "),
      exp: Math.floor(Date.now() / 1000) + expiresIn,
      sub: "private-test-subject", aud: resource.href, iss: issuer.href
    })) as unknown as typeof fetch
  };
}
type RpcReply = {
  jsonrpc: string; id?: number;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
};
function parseRpc(raw: string): RpcReply {
  const text = raw.trimStart().startsWith("{") ? raw :
    raw.split(/\r?\n/).filter(line => line.startsWith("data:"))
      .map(line => line.slice(5).trim()).join("\n");
  return JSON.parse(text) as RpcReply;
}
async function rpc(
  handler: ReturnType<typeof createKyntralHttpHandler>,
  method: string, params: Record<string, unknown>,
  protocolVersion = "2025-11-25"
): Promise<{ response: Response; body: RpcReply }> {
  const response = await handler(new Request(resource, {
    method: "POST",
    headers: {
      authorization: "Bearer test-token",
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "mcp-protocol-version": protocolVersion
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 7, method, params: protocolVersion === "2026-07-28" ? { ...params, _meta: {} } : params })
  }));
  return { response, body: parseRpc(await response.text()) };
}
function init(version: string): Record<string, unknown> {
  return {
    protocolVersion: version, capabilities: {},
    clientInfo: { name: "kyntral-regression-test", version: "1.0.0" }
  };
}
describe("MCP SDK 2.4.0 HTTP transport and authorization", () => {
  it("initializes legacy protocol 2025-11-25", async () => {
    const handler = createKyntralHttpHandler(config([KYNTRAL_SCOPES.read]));
    const { response, body } = await rpc(handler, "initialize", init("2025-11-25"));
    expect(response.status).toBe(200);
    expect(body.error).toBeUndefined();
    expect(body.result?.protocolVersion).toBe("2025-11-25");
    expect(body.result?.serverInfo).toMatchObject({ name: "kyntral" });
  });
  it("rejects a legacy handshake with a modern protocol header", async () => {
    const handler = createKyntralHttpHandler(config([KYNTRAL_SCOPES.read]));
    const { response, body } = await rpc(
      handler, "initialize", init("2026-07-28"), "2026-07-28"
    );
    expect(response.status).toBe(400);
    expect(body.error?.code).toBe(-32020);
    expect(body.error?.message).toContain("headers and body disagree");
  });
  it("accepts modern 2026-07-28 tools/list without a legacy handshake", async () => {
    const handler = createKyntralHttpHandler(config([KYNTRAL_SCOPES.read]));
    const { response, body } = await rpc(handler, "tools/list", {}, "2026-07-28");
    expect(response.status, JSON.stringify(body)).toBe(200);
    expect(body.error).toBeUndefined();
    const tools = body.result?.tools as Array<{ name: string }>;
    expect(tools.map(t => t.name)).toContain("kyntral_get_profile");
  });
  it("advertises typed tools but no generic execution", async () => {
    const handler = createKyntralHttpHandler(config([KYNTRAL_SCOPES.read]));
    const { response, body } = await rpc(handler, "tools/list", {});
    expect(response.status).toBe(200);
    expect(body.error).toBeUndefined();
    const tools = body.result?.tools as Array<{
      name: string; inputSchema: Record<string, unknown>;
    }>;
    expect(Array.isArray(tools)).toBe(true);
    const names = tools.map(t => t.name);
    expect(names).toContain("kyntral_get_profile");
    expect(names).toContain("kyntral_queue_workflow");
    for (const forbidden of ["execute_anything", "arbitrary_shell", "arbitrary_url"]) {
      expect(names).not.toContain(forbidden);
    }
    for (const tool of tools) expect(tool.inputSchema.type).toBe("object");
  });
  it("returns an opaque principal and structured result for an authorized read", async () => {
    const handler = createKyntralHttpHandler(config([KYNTRAL_SCOPES.read]));
    const { response, body } = await rpc(handler, "tools/call", {
      name: "kyntral_get_profile", arguments: {}
    });
    expect(response.status).toBe(200);
    expect(body.error).toBeUndefined();
    const expected = deriveOpaquePrincipalId(issuer, "private-test-subject");
    const result = body.result as { structuredContent?: { id: string } };
    expect(result.structuredContent).toEqual({ id: expected });
    expect(JSON.stringify(body)).not.toContain("private-test-subject");
  });
  it("prevents queueing without execution scope", async () => {
    const settings = config([KYNTRAL_SCOPES.read]);
    const store = settings.store as SqliteKyntralStore;
    const put = vi.spyOn(store, "putAuthorizedJob");
    const handler = createKyntralHttpHandler(settings);
    const { response, body } = await rpc(handler, "tools/call", {
      name: "kyntral_queue_workflow",
      arguments: {
        deviceId: "dev_test_001", scopeId: "scope_test_001",
        workflowId: "wf_test_001"
      }
    });
    expect(response.status === 403 || body.error !== undefined ||
      (body.result as { isError?: boolean } | undefined)?.isError === true).toBe(true);
    expect(put).not.toHaveBeenCalled();
  });
  it("rejects malformed tool input rather than coercing it", async () => {
    const handler = createKyntralHttpHandler(config([KYNTRAL_SCOPES.read]));
    const { response, body } = await rpc(handler, "tools/call", {
      name: "kyntral_get_device", arguments: { deviceId: 123 }
    });
    expect(response.status >= 400 || body.error !== undefined ||
      (body.result as { isError?: boolean } | undefined)?.isError === true).toBe(true);
  });
  it("returns 405 with Allow: POST for non-POST MCP requests", async () => {
    const handler = createKyntralHttpHandler(config([KYNTRAL_SCOPES.read]));
    const response = await handler(new Request(resource, {
      method: "GET", headers: { authorization: "Bearer test-token" }
    }));
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
  });
  it("rejects requests without a bearer token", async () => {
    const handler = createKyntralHttpHandler(config([KYNTRAL_SCOPES.read]));
    const response = await handler(new Request(resource, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 8, method: "tools/list" })
    }));
    expect(response.status).toBe(401);
  });
  for (const scenario of [
    { name: "inactive", active: false, expiresIn: 300 },
    { name: "expired", active: true, expiresIn: -30 }
  ]) {
    it("rejects " + scenario.name + " OAuth credentials", async () => {
      const handler = createKyntralHttpHandler(
        config([KYNTRAL_SCOPES.read], scenario.active, scenario.expiresIn)
      );
      const response = await handler(new Request(resource, {
        method: "POST",
        headers: {
          authorization: "Bearer test-token",
          "content-type": "application/json",
          accept: "application/json, text/event-stream"
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list" })
      }));
      expect(response.status).toBe(401);
    });
  }
});

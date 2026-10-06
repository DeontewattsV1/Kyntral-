// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from "vitest";
import {
  IntrospectionTokenVerifier,
  deriveOpaquePrincipalId
} from "../src/oauth.js";

const issuer = new URL("https://identity.example.test/");
const resource = new URL("https://api.example.test/mcp");

function response(body: unknown, status = 200): Response {
  return Response.json(body, { status });
}

describe("IntrospectionTokenVerifier", () => {
  it("maps a valid token to opaque Kyntral principal context", async () => {
    const fetchFn = vi.fn(async () =>
      response({
        active: true,
        client_id: "openai-client",
        scope: "kyntral.read kyntral.execute",
        exp: Math.floor(Date.now() / 1000) + 300,
        sub: "provider-user-123",
        aud: resource.href,
        iss: issuer.href
      })
    );

    const verifier = new IntrospectionTokenVerifier({
      issuer,
      introspectionUrl: new URL("https://identity.example.test/introspect"),
      clientId: "resource-server",
      clientSecret: "test-secret",
      expectedResource: resource,
      fetchFn
    });

    const info = await verifier.verifyAccessToken("token-123");
    expect(info.clientId).toBe("openai-client");
    expect(info.scopes).toEqual(["kyntral.read", "kyntral.execute"]);
    expect(info.resource?.href).toBe(resource.href);
    expect(info.extra?.kyntralPrincipalId).toBe(
      deriveOpaquePrincipalId(issuer, "provider-user-123")
    );
    expect(JSON.stringify(info.extra)).not.toContain("provider-user-123");
  });

  it("rejects inactive tokens", async () => {
    const verifier = new IntrospectionTokenVerifier({
      issuer,
      introspectionUrl: new URL("https://identity.example.test/introspect"),
      clientId: "resource-server",
      clientSecret: "test-secret",
      expectedResource: resource,
      fetchFn: vi.fn(async () => response({ active: false }))
    });

    await expect(verifier.verifyAccessToken("bad-token"))
      .rejects.toMatchObject({ code: "invalid_token" });
  });

  it("rejects tokens issued for a different MCP resource", async () => {
    const verifier = new IntrospectionTokenVerifier({
      issuer,
      introspectionUrl: new URL("https://identity.example.test/introspect"),
      clientId: "resource-server",
      clientSecret: "test-secret",
      expectedResource: resource,
      fetchFn: vi.fn(async () =>
        response({
          active: true,
          client_id: "grok-client",
          scope: ["kyntral.read"],
          exp: Math.floor(Date.now() / 1000) + 300,
          sub: "provider-user-123",
          aud: "https://other.example.test/mcp",
          iss: issuer.href
        })
      )
    });

    await expect(verifier.verifyAccessToken("wrong-audience"))
      .rejects.toMatchObject({ code: "invalid_token" });
  });

  it("requires HTTPS for all production OAuth endpoints", () => {
    expect(() => new IntrospectionTokenVerifier({
      issuer: new URL("http://identity.example.test/"),
      introspectionUrl: new URL("https://identity.example.test/introspect"),
      clientId: "resource-server",
      clientSecret: "test-secret",
      expectedResource: resource
    })).toThrow(/HTTPS/);
  });
});

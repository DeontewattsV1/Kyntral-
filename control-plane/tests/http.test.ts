// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from "vitest";
import { createKyntralHttpHandler, type KyntralHttpConfig } from "../src/http.js";

const resource = new URL("https://api.example.test/mcp");
const issuer = new URL("https://identity.example.test/");

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

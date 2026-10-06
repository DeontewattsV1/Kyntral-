// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import {
  IntrospectionTokenVerifier,
  deriveOpaquePrincipalId
} from "../control-plane/src/oauth.js";

describe("AUTHN-001 provider identity minimization", () => {
  it("derives stable opaque principals without exposing raw provider subject", () => {
    const issuer = new URL("https://identity.example.test/");
    const first = deriveOpaquePrincipalId(issuer, "raw-provider-subject");
    const second = deriveOpaquePrincipalId(issuer, "raw-provider-subject");
    expect(first).toBe(second);
    expect(first).toMatch(/^usr_[A-Za-z0-9_-]{32}$/);
    expect(first).not.toContain("raw-provider-subject");
  });
});

describe("AUTHN-002 exact OAuth resource binding", () => {
  it("rejects a token for another MCP resource", async () => {
    const verifier = new IntrospectionTokenVerifier({
      issuer: new URL("https://identity.example.test/"),
      introspectionUrl: new URL("https://identity.example.test/introspect"),
      clientId: "resource-server",
      clientSecret: "test-secret",
      expectedResource: new URL("https://api.example.test/mcp"),
      fetchFn: vi.fn(async () =>
        Response.json({
          active: true,
          client_id: "provider-client",
          scope: "kyntral.read",
          exp: Math.floor(Date.now() / 1000) + 300,
          sub: "user",
          aud: "https://different.example.test/mcp"
        })
      )
    });

    await expect(verifier.verifyAccessToken("token"))
      .rejects.toMatchObject({ code: "invalid_token" });
  });
});

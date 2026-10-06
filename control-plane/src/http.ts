// SPDX-License-Identifier: BUSL-1.1

import {
  createMcpHandler,
  getOAuthProtectedResourceMetadataUrl,
  requireBearerAuth
} from "@modelcontextprotocol/server";
import { IntrospectionTokenVerifier } from "./oauth.js";
import { KYNTRAL_SCOPES, createKyntralServer } from "./server.js";
import { SqliteKyntralStore } from "./store.js";

export type KyntralHttpConfig = Readonly<{
  publicMcpUrl: URL;
  oauthIssuer: URL;
  oauthIntrospectionUrl: URL;
  oauthClientId: string;
  oauthClientSecret: string;
  databasePath: string;
}>;

function requireProductionHttps(url: URL, field: string): void {
  if (url.protocol !== "https:") {
    throw new Error(field + " must use HTTPS");
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
    "KYNTRAL_OAUTH_CLIENT_SECRET"
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
    databasePath: env.KYNTRAL_DB_PATH ?? "./data/kyntral.db"
  };
}

export function createKyntralHttpHandler(config: KyntralHttpConfig) {
  const store = new SqliteKyntralStore(config.databasePath);
  const mcpHandler = createMcpHandler(() =>
    createKyntralServer({ store })
  );
  const resourceMetadataUrl =
    getOAuthProtectedResourceMetadataUrl(config.publicMcpUrl);

  const gate = requireBearerAuth({
    verifier: new IntrospectionTokenVerifier({
      issuer: config.oauthIssuer,
      introspectionUrl: config.oauthIntrospectionUrl,
      clientId: config.oauthClientId,
      clientSecret: config.oauthClientSecret,
      expectedResource: config.publicMcpUrl
    }),
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

    if (url.pathname !== "/mcp") {
      return new Response("Not Found", { status: 404 });
    }

    const authInfo = await gate(request);
    if (authInfo instanceof Response) return authInfo;

    return mcpHandler.fetch(request, { authInfo });
  };
}

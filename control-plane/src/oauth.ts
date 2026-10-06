// SPDX-License-Identifier: BUSL-1.1

import { createHash } from "node:crypto";
import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type OAuthTokenVerifier
} from "@modelcontextprotocol/server";

export type OAuthIntrospection = Readonly<{
  active?: boolean;
  client_id?: string;
  scope?: string | string[];
  exp?: number;
  sub?: string;
  aud?: string | string[];
  iss?: string;
}>;

export type IntrospectionTokenVerifierOptions = Readonly<{
  issuer: URL;
  introspectionUrl: URL;
  clientId: string;
  clientSecret: string;
  expectedResource: URL;
  fetchFn?: typeof fetch;
}>;

function requireHttps(url: URL, field: string): void {
  if (url.protocol !== "https:") {
    throw new Error(field + " must use HTTPS");
  }
}

function normalizeScopes(scope: OAuthIntrospection["scope"]): string[] {
  if (Array.isArray(scope)) {
    return [...new Set(scope.filter((value) => value.length > 0))];
  }
  if (typeof scope === "string") {
    return [...new Set(scope.split(/\s+/).filter(Boolean))];
  }
  return [];
}

function audienceIncludes(
  audience: OAuthIntrospection["aud"],
  expectedResource: URL
): boolean {
  const expected = expectedResource.href.replace(/\/$/, "");
  const values = Array.isArray(audience) ? audience : [audience];
  return values.some((value) => {
    if (typeof value !== "string") return false;
    try {
      return new URL(value).href.replace(/\/$/, "") === expected;
    } catch {
      return false;
    }
  });
}

export function deriveOpaquePrincipalId(issuer: URL, subject: string): string {
  const digest = createHash("sha256")
    .update(issuer.href)
    .update("\0")
    .update(subject)
    .digest("base64url")
    .slice(0, 32);
  return "usr_" + digest;
}

function invalidToken(message: string): never {
  throw new OAuthError(OAuthErrorCode.InvalidToken, message);
}

export class IntrospectionTokenVerifier implements OAuthTokenVerifier {
  readonly #fetch: typeof fetch;

  constructor(
    private readonly options: IntrospectionTokenVerifierOptions
  ) {
    requireHttps(options.issuer, "issuer");
    requireHttps(options.introspectionUrl, "introspectionUrl");
    requireHttps(options.expectedResource, "expectedResource");
    if (!options.clientId || !options.clientSecret) {
      throw new Error("OAuth introspection client credentials are required");
    }
    this.#fetch = options.fetchFn ?? fetch;
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    if (!token) invalidToken("missing bearer token");

    const body = new URLSearchParams({
      token,
      token_type_hint: "access_token"
    });
    const basic = Buffer
      .from(this.options.clientId + ":" + this.options.clientSecret, "utf8")
      .toString("base64");

    let response: Response;
    try {
      response = await this.#fetch(this.options.introspectionUrl, {
        method: "POST",
        headers: {
          authorization: "Basic " + basic,
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json"
        },
        body
      });
    } catch {
      throw new OAuthError(
        OAuthErrorCode.ServerError,
        "OAuth introspection endpoint unavailable"
      );
    }

    if (!response.ok) {
      if (response.status === 400 || response.status === 401) {
        invalidToken("access token could not be introspected");
      }
      throw new OAuthError(
        OAuthErrorCode.ServerError,
        "OAuth introspection endpoint failed"
      );
    }

    const result = await response.json() as OAuthIntrospection;
    if (result.active !== true) invalidToken("inactive access token");
    if (!result.sub) invalidToken("access token is missing subject");
    if (!result.client_id) invalidToken("access token is missing client_id");
    if (!Number.isFinite(result.exp)) invalidToken("access token is missing exp");

    const nowSeconds = Math.floor(Date.now() / 1000);
    if ((result.exp as number) <= nowSeconds) invalidToken("access token is expired");

    if (result.iss && new URL(result.iss).href !== this.options.issuer.href) {
      invalidToken("access token issuer mismatch");
    }

    if (!audienceIncludes(result.aud, this.options.expectedResource)) {
      invalidToken("access token audience mismatch");
    }

    return {
      token,
      clientId: result.client_id,
      scopes: normalizeScopes(result.scope),
      expiresAt: result.exp,
      resource: new URL(this.options.expectedResource),
      extra: {
        kyntralPrincipalId: deriveOpaquePrincipalId(
          this.options.issuer,
          result.sub
        )
      }
    };
  }
}

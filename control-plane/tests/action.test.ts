// SPDX-License-Identifier: BUSL-1.1

import {
  generateKeyPairSync,
  type JsonWebKey
} from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  Es256ActionSigner,
  issueSignedAction,
  type P256PrivateJwk
} from "../src/action.js";
import {
  verifyActionAuthorization
} from "../src/crypto.js";

function signer(): Es256ActionSigner {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const raw = pair.privateKey.export({ format: "jwk" }) as JsonWebKey;
  return new Es256ActionSigner({
    kty: "EC",
    crv: "P-256",
    x: String(raw.x),
    y: String(raw.y),
    d: String(raw.d),
    kid: "auth_test_001",
    use: "sig",
    alg: "ES256"
  } satisfies P256PrivateJwk);
}

describe("signed action issuance", () => {
  it("issues a five-minute ES256 authorization bound to the exact query", () => {
    const actionSigner = signer();
    const issued = issueSignedAction({
      actionId: "act_issue_001",
      query: {
        principalId: "usr_issue_001",
        deviceId: "dev_issue_001",
        scopeId: "scope_issue_001",
        workflowId: "wf_media",
        capability: "workflow.execute",
        risk: "K2"
      },
      signer: actionSigner,
      now: new Date("2026-10-07T01:00:00.000Z")
    });

    expect(issued.action.issuedAt).toBe("2026-10-07T01:00:00.000Z");
    expect(issued.action.expiresAt).toBe("2026-10-07T01:05:00.000Z");
    expect(issued.action.nonce).toHaveLength(43);
    expect(issued.action.authorizationProof.keyId).toBe("auth_test_001");
    expect(
      verifyActionAuthorization(issued.action, actionSigner.publicKey)
    ).toBe(true);
  });

  it("rejects a non-signing or incomplete private JWK", () => {
    expect(() => new Es256ActionSigner({
      kty: "EC",
      crv: "P-256",
      x: "x",
      y: "y",
      d: "",
      kid: "bad_key",
      use: "sig",
      alg: "ES256"
    })).toThrow(/private JWK/i);
  });
});

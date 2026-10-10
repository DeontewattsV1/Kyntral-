// SPDX-License-Identifier: BUSL-1.1

import {
  createPrivateKey,
  randomBytes,
  sign as signMessage,
  type JsonWebKey,
  type KeyObject
} from "node:crypto";
import type { AuthorizationQuery } from "./authorization.js";
import {
  computeActionHash,
  signingPreimage,
  type CanonicalJson,
  type Es256Proof,
  type P256PublicJwk,
  type SignedActionEnvelope
} from "./crypto.js";
import { MAX_ACTION_LIFETIME_MS } from "./time.js";

export type P256PrivateJwk = P256PublicJwk & Readonly<{ d: string }>;

export type IssuedAction = Readonly<{
  action: SignedActionEnvelope;
  authorizationKey: P256PublicJwk;
  actionHash: string;
}>;

export class Es256ActionSigner {
  readonly publicKey: P256PublicJwk;
  readonly #privateKey: KeyObject;

  constructor(jwk: P256PrivateJwk) {
    if (
      jwk.kty !== "EC" ||
      jwk.crv !== "P-256" ||
      jwk.use !== "sig" ||
      jwk.alg !== "ES256" ||
      !jwk.kid ||
      !jwk.d
    ) {
      throw new Error("Kyntral action signing key must be a P-256 ES256 private JWK");
    }

    this.#privateKey = createPrivateKey({
      key: jwk as JsonWebKey,
      format: "jwk"
    });
    this.publicKey = Object.freeze({
      kty: "EC",
      crv: "P-256",
      x: jwk.x,
      y: jwk.y,
      kid: jwk.kid,
      use: "sig",
      alg: "ES256"
    });
  }

  sign(preimage: Buffer): string {
    return signMessage("sha256", preimage, this.#privateKey).toString("base64url");
  }
}

export function issueSignedAction(input: {
  actionId: string;
  query: AuthorizationQuery;
  signer: Es256ActionSigner;
  now?: Date;
}): IssuedAction {
  const now = input.now ?? new Date();
  const issuedAt = now.toISOString();
  const expiresAt = new Date(
    now.getTime() + MAX_ACTION_LIFETIME_MS
  ).toISOString();

  const unsigned = {
    version: "kyntral.action.v1" as const,
    actionId: input.actionId,
    deviceId: input.query.deviceId,
    scopeId: input.query.scopeId,
    workflowId: input.query.workflowId,
    capability: input.query.capability,
    risk: input.query.risk,
    nonce: randomBytes(32).toString("base64url"),
    issuedAt,
    expiresAt,
    idempotencyKey: "idem_" + randomBytes(18).toString("base64url")
  };

  const signature = input.signer.sign(
    signingPreimage(
      "action-authorization",
      unsigned as unknown as CanonicalJson
    )
  );
  const authorizationProof: Es256Proof = {
    keyId: input.signer.publicKey.kid,
    algorithm: "ES256",
    signature
  };

  const action: SignedActionEnvelope = Object.freeze({
    ...unsigned,
    authorizationProof
  });

  return Object.freeze({
    action,
    authorizationKey: input.signer.publicKey,
    actionHash: computeActionHash(action)
  });
}

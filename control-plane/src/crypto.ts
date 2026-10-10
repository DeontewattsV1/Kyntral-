// SPDX-License-Identifier: BUSL-1.1

import {
  createHash,
  createPublicKey,
  verify as verifySignature,
  type JsonWebKey
} from "node:crypto";

export type CanonicalJson =
  | null
  | boolean
  | string
  | number
  | CanonicalJson[]
  | { [key: string]: CanonicalJson };

export type P256PublicJwk = Readonly<{
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  kid: string;
  use: "sig" | "enc";
  alg: "ES256" | "ECDH-ES";
}>;

export type Es256Proof = Readonly<{
  keyId: string;
  algorithm: "ES256";
  signature: string;
}>;

export type SignedActionEnvelope = Readonly<{
  version: "kyntral.action.v1";
  actionId: string;
  deviceId: string;
  scopeId: string;
  workflowId: string;
  capability: string;
  risk: "K0" | "K1" | "K2" | "K3" | "K4";
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  idempotencyKey: string;
  authorizationProof: Es256Proof;
}>;

export type ExecutionReceipt = Readonly<{
  version: "kyntral.receipt.v1";
  receiptId: string;
  actionId: string;
  deviceId: string;
  actionHash: string;
  outcome: "completed" | "partial" | "failed" | "cancelled";
  startedAt: string;
  completedAt: string;
  counts: Readonly<{ completed: number; failed: number }>;
  deviceProof: Es256Proof;
}>;

function canonicalString(value: string): string {
  return JSON.stringify(value.normalize("NFC"));
}

function compareUtf8(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

export function canonicalizeJson(value: CanonicalJson): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";

  if (typeof value === "string") {
    return canonicalString(value);
  }

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("KCJ-1 accepts safe integers only");
    }
    return String(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeJson).join(",")}]`;
  }

  const normalized = new Map<string, CanonicalJson>();
  for (const [rawKey, nested] of Object.entries(value)) {
    const key = rawKey.normalize("NFC");
    if (normalized.has(key)) {
      throw new Error("KCJ-1 object contains duplicate keys after NFC normalization");
    }
    normalized.set(key, nested);
  }

  const keys = [...normalized.keys()].sort(compareUtf8);
  return `{${keys
    .map((key) => `${canonicalString(key)}:${canonicalizeJson(normalized.get(key)!)}`)
    .join(",")}}`;
}

export function signingPreimage(
  purpose:
    | "action-authorization"
    | "execution-receipt"
    | "pairing-proof"
    | "device-request",
  value: CanonicalJson
): Buffer {
  const prefix = Buffer.from(`KYNTRAL\0${purpose}\0v1\0`, "utf8");
  return Buffer.concat([prefix, Buffer.from(canonicalizeJson(value), "utf8")]);
}

export function sha256Canonical(value: CanonicalJson): string {
  return `sha256:${createHash("sha256")
    .update(Buffer.from(canonicalizeJson(value), "utf8"))
    .digest("hex")}`;
}

export function decodeBase64Url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid base64url value");
  }
  return Buffer.from(value, "base64url");
}

function toNodeJwk(jwk: P256PublicJwk): JsonWebKey {
  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    kid: jwk.kid,
    use: jwk.use,
    alg: jwk.alg
  };
}

export function verifyEs256(
  publicKey: P256PublicJwk,
  preimage: Buffer,
  signatureBase64Url: string
): boolean {
  if (
    publicKey.kty !== "EC" ||
    publicKey.crv !== "P-256" ||
    publicKey.use !== "sig" ||
    publicKey.alg !== "ES256"
  ) {
    return false;
  }

  const key = createPublicKey({
    key: toNodeJwk(publicKey),
    format: "jwk"
  });

  return verifySignature(
    "sha256",
    preimage,
    key,
    decodeBase64Url(signatureBase64Url)
  );
}

export function unsignedActionProjection(
  action: SignedActionEnvelope
): CanonicalJson {
  const { authorizationProof: _proof, ...unsigned } = action;
  return unsigned as CanonicalJson;
}

export function actionAuthorizationPreimage(
  action: SignedActionEnvelope
): Buffer {
  return signingPreimage("action-authorization", unsignedActionProjection(action));
}

export function computeActionHash(action: SignedActionEnvelope): string {
  return sha256Canonical(action as unknown as CanonicalJson);
}

export function verifyActionAuthorization(
  action: SignedActionEnvelope,
  authorizationKey: P256PublicJwk
): boolean {
  return (
    action.authorizationProof.algorithm === "ES256" &&
    action.authorizationProof.keyId === authorizationKey.kid &&
    verifyEs256(
      authorizationKey,
      actionAuthorizationPreimage(action),
      action.authorizationProof.signature
    )
  );
}

export function unsignedReceiptProjection(
  receipt: ExecutionReceipt
): CanonicalJson {
  const { deviceProof: _proof, ...unsigned } = receipt;
  return unsigned as CanonicalJson;
}

export function receiptSigningPreimage(receipt: ExecutionReceipt): Buffer {
  return signingPreimage("execution-receipt", unsignedReceiptProjection(receipt));
}

export function verifyReceiptBinding(
  action: SignedActionEnvelope,
  receipt: ExecutionReceipt,
  deviceSigningKey: P256PublicJwk
): boolean {
  if (receipt.actionId !== action.actionId) return false;
  if (receipt.deviceId !== action.deviceId) return false;
  if (receipt.actionHash !== computeActionHash(action)) return false;
  if (receipt.deviceProof.keyId !== deviceSigningKey.kid) return false;
  if (receipt.deviceProof.algorithm !== "ES256") return false;

  return verifyEs256(
    deviceSigningKey,
    receiptSigningPreimage(receipt),
    receipt.deviceProof.signature
  );
}

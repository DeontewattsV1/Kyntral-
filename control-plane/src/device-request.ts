// SPDX-License-Identifier: BUSL-1.1

import { createHash } from "node:crypto";
import {
  decodeBase64Url,
  signingPreimage,
  verifyEs256,
  type CanonicalJson,
  type Es256Proof,
  type P256PublicJwk
} from "./crypto.js";
import type { KyntralStore } from "./store.js";
import { assertTemporalWindow } from "./time.js";

export const DEVICE_REQUEST_PROOF_HEADER = "x-kyntral-device-proof";
export const MAX_DEVICE_REQUEST_LIFETIME_MS = 60_000;
export const DEVICE_REQUEST_CLOCK_SKEW_MS = 30_000;
export const MAX_DEVICE_REQUEST_PROOF_HEADER_BYTES = 4_096;

export type DeviceRequestProof = Readonly<{
  version: "kyntral.device-request.v1";
  deviceId: string;
  method: "GET" | "POST";
  path: string;
  bodyHash: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  proof: Es256Proof;
}>;

export function sha256Bytes(data: Uint8Array): string {
  return "sha256:" + createHash("sha256").update(data).digest("hex");
}

export function unsignedDeviceRequestProjection(
  request: DeviceRequestProof
): CanonicalJson {
  const { proof: _proof, ...unsigned } = request;
  return unsigned as CanonicalJson;
}

export function deviceRequestSigningPreimage(
  request: DeviceRequestProof
): Buffer {
  return signingPreimage(
    "device-request",
    unsignedDeviceRequestProjection(request)
  );
}

export function encodeDeviceRequestHeader(
  proof: DeviceRequestProof
): string {
  return Buffer.from(JSON.stringify(proof), "utf8").toString("base64url");
}

export function decodeDeviceRequestHeader(
  value: string
): DeviceRequestProof {
  if (
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") >
      MAX_DEVICE_REQUEST_PROOF_HEADER_BYTES
  ) {
    throw new Error("invalid device request proof header");
  }

  const decoded = decodeBase64Url(value).toString("utf8");
  const parsed = JSON.parse(decoded) as DeviceRequestProof;
  return parsed;
}

function signingKey(identityJson: string): P256PublicJwk {
  const identity = JSON.parse(identityJson) as {
    signingPublicKey?: P256PublicJwk;
  };
  const key = identity.signingPublicKey;
  if (!key) {
    throw new Error("paired device is missing signing identity");
  }
  return key;
}

function validateShape(proof: DeviceRequestProof): void {
  if (proof.version !== "kyntral.device-request.v1") {
    throw new Error("invalid device request proof version");
  }
  if (!/^[A-Za-z][A-Za-z0-9_-]{2,127}$/.test(proof.deviceId)) {
    throw new Error("invalid device request deviceId");
  }
  if (proof.method !== "GET" && proof.method !== "POST") {
    throw new Error("invalid device request method");
  }
  if (
    !proof.path.startsWith("/") ||
    proof.path.includes("?") ||
    proof.path.includes("#")
  ) {
    throw new Error("invalid device request path");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(proof.bodyHash)) {
    throw new Error("invalid device request body hash");
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(proof.nonce)) {
    throw new Error("invalid device request nonce");
  }
  if (
    proof.proof.algorithm !== "ES256" ||
    !proof.proof.keyId ||
    !/^[A-Za-z0-9_-]+$/.test(proof.proof.signature)
  ) {
    throw new Error("invalid device request signature proof");
  }
}

export function verifyAndConsumeDeviceRequest(input: {
  store: KyntralStore;
  proof: DeviceRequestProof;
  expectedDeviceId: string;
  method: "GET" | "POST";
  path: string;
  body: Uint8Array;
  now?: Date;
}): void {
  const now = input.now ?? new Date();
  validateShape(input.proof);

  if (input.proof.deviceId !== input.expectedDeviceId) {
    throw new Error("device request device mismatch");
  }
  if (input.proof.method !== input.method) {
    throw new Error("device request method mismatch");
  }
  if (input.proof.path !== input.path) {
    throw new Error("device request path mismatch");
  }
  if (input.proof.bodyHash !== sha256Bytes(input.body)) {
    throw new Error("device request body hash mismatch");
  }

  assertTemporalWindow({
    issuedAt: input.proof.issuedAt,
    expiresAt: input.proof.expiresAt,
    now,
    maxLifetimeMs: MAX_DEVICE_REQUEST_LIFETIME_MS,
    clockSkewMs: DEVICE_REQUEST_CLOCK_SKEW_MS
  });

  const device = input.store.getDevice(input.expectedDeviceId);
  if (!device || device.revokedAt !== null) {
    throw new Error("device request device is unavailable");
  }

  const key = signingKey(device.identityJson);
  if (
    input.proof.proof.keyId !== key.kid ||
    !verifyEs256(
      key,
      deviceRequestSigningPreimage(input.proof),
      input.proof.proof.signature
    )
  ) {
    throw new Error("invalid device request signature");
  }

  const expiryWithSkew = new Date(
    Date.parse(input.proof.expiresAt) +
      DEVICE_REQUEST_CLOCK_SKEW_MS
  ).toISOString();

  if (!input.store.consumeNonce(
    "device-request:" + input.expectedDeviceId,
    input.proof.nonce,
    expiryWithSkew,
    now
  )) {
    throw new Error("device request replay detected");
  }
}

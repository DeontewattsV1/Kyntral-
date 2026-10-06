// SPDX-License-Identifier: BUSL-1.1

export const MAX_CLOCK_SKEW_MS = 60_000;
export const MAX_ACTION_LIFETIME_MS = 5 * 60_000;
export const MAX_PAIRING_LIFETIME_MS = 5 * 60_000;

function parseInstant(value: string, field: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${field} must be a valid RFC 3339 timestamp`);
  }
  return parsed;
}

export function assertTemporalWindow(input: {
  issuedAt: string;
  expiresAt: string;
  now?: Date;
  maxLifetimeMs: number;
  clockSkewMs?: number;
}): void {
  const nowMs = (input.now ?? new Date()).getTime();
  const issuedMs = parseInstant(input.issuedAt, "issuedAt");
  const expiresMs = parseInstant(input.expiresAt, "expiresAt");
  const skew = input.clockSkewMs ?? MAX_CLOCK_SKEW_MS;

  if (expiresMs <= issuedMs) {
    throw new Error("expiresAt must be after issuedAt");
  }
  if (expiresMs - issuedMs > input.maxLifetimeMs) {
    throw new Error("authorization lifetime exceeds protocol maximum");
  }
  if (issuedMs > nowMs + skew) {
    throw new Error("issuedAt is too far in the future");
  }
  if (nowMs > expiresMs + skew) {
    throw new Error("authorization is expired");
  }
}

export function assertActionTimeWindow(input: {
  issuedAt: string;
  expiresAt: string;
  now?: Date;
}): void {
  assertTemporalWindow({
    ...input,
    maxLifetimeMs: MAX_ACTION_LIFETIME_MS
  });
}

export function assertPairingTimeWindow(input: {
  issuedAt: string;
  expiresAt: string;
  now?: Date;
}): void {
  assertTemporalWindow({
    ...input,
    maxLifetimeMs: MAX_PAIRING_LIFETIME_MS
  });
}

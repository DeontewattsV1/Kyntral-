// SPDX-License-Identifier: BUSL-1.1

export const MAX_CLOCK_SKEW_MS = 60_000;
export const MAX_ACTION_LIFETIME_MS = 5 * 60_000;
export const MAX_PAIRING_LIFETIME_MS = 5 * 60_000;

export function parseInstant(value: string, field: string): number {
  // Millisecond-resolution RFC3339 profile; reject calendar normalization.
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  const parsed = Date.parse(value);
  const local = match ? Date.parse(`${match[1]}T${match[2]}Z`) : NaN;
  const zone = match?.[3];
  const validZone = zone === "Z" || (zone !== undefined && zone !== "-00:00" &&
    Number(zone.slice(1, 3)) <= 23 && Number(zone.slice(4)) <= 59);
  if (!match || !validZone || !Number.isFinite(parsed) || !Number.isFinite(local) ||
      new Date(local).toISOString().slice(0, 19) !== `${match[1]}T${match[2]}`) {
    throw new Error(`${field} must be a valid millisecond RFC 3339 timestamp`);
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

  if (!Number.isFinite(nowMs)) throw new Error("now must be a valid timestamp");
  if (!Number.isFinite(skew) || skew < 0 ||
      !Number.isFinite(input.maxLifetimeMs) || input.maxLifetimeMs <= 0) {
    throw new Error("invalid temporal policy");
  }

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

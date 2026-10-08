// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it } from "vitest";
import { assertTemporalWindow, assertActionTimeWindow, assertPairingTimeWindow } from "../src/time.js";
import { SqliteKyntralStore } from "../src/store.js";

const issuedAt = "2026-10-07T00:00:00.000Z";
const expiresAt = "2026-10-07T00:05:00.000Z";
describe("temporal fail-closed boundaries", () => {
  for (const validate of [assertActionTimeWindow, assertPairingTimeWindow]) {
    it("rejects invalid clocks and preserves inclusive skew endpoints", () => {
      expect(() => validate({ issuedAt, expiresAt, now: new Date(NaN) })).toThrow();
      for (const offset of [-60_000, 360_000]) {
        expect(() => validate({ issuedAt, expiresAt, now: new Date(Date.parse(issuedAt) + offset) })).not.toThrow();
      }
      for (const offset of [-60_001, 360_001]) {
        expect(() => validate({ issuedAt, expiresAt, now: new Date(Date.parse(issuedAt) + offset) })).toThrow();
      }
    });
  }
  it.each([NaN, Infinity, -1])("rejects invalid skew %s", (clockSkewMs) => {
    expect(() => assertTemporalWindow({ issuedAt, expiresAt, clockSkewMs, maxLifetimeMs: 300_000 })).toThrow();
  });
  it("does not consume a nonce on malformed temporal evidence", () => {
    const store = new SqliteKyntralStore(":memory:");
    try {
      const now = new Date(issuedAt);
      expect(store.consumeNonce("test", "nonce", "invalid", now)).toBe(false);
      expect(store.consumeNonce("test", "nonce", expiresAt, new Date(NaN))).toBe(false);
      expect(store.consumeNonce("test", "nonce", issuedAt, now)).toBe(true);
      expect(store.consumeNonce("test", "nonce", expiresAt, now)).toBe(false);
    } finally { store.close(); }
  });
});

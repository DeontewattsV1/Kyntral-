// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseCapabilityManifestV1 } from "../sdk/src/index.js";

describe("CAP-001 Capability Manifest v1", () => {
  for (const example of [
    "media-intake.capability.json",
    "local-file-sort.capability.json"
  ]) {
    it("accepts extension example: " + example, () => {
      const manifest = JSON.parse(readFileSync(
        new URL("../sdk/examples/" + example, import.meta.url),
        "utf8"
      ));
      expect(parseCapabilityManifestV1(manifest).version)
        .toBe("kyntral.capability.v1");
    });
  }

  it("rejects arbitrary network access", () => {
    expect(() => parseCapabilityManifestV1({
      version: "kyntral.capability.v1",
      id: "org.example.bad",
      moduleVersion: "0.1.0",
      publisher: { id: "example_org", name: "Example" },
      risk: "K2",
      execution: { location: "device", backgroundAllowed: false },
      deviceData: ["files"],
      network: { access: "allowlist", domains: ["*"] },
      sideEffects: ["network-read"]
    })).toThrow();
  });
});

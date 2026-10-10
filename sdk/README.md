# Kyntral SDK

SPDX-License-Identifier: Apache-2.0

The Kyntral SDK makes the public capability contract portable without transferring runtime authority to an extension.

## v0.1 RC surface

The repository now includes a small TypeScript protocol-facing SDK under `sdk/src/`:

- `CapabilityManifestV1`
- K0–K4 risk types
- execution-location types
- device-data categories
- network allowlist declarations
- side-effect declarations
- `assertCapabilityManifestV1()`
- `parseCapabilityManifestV1()`

The canonical JSON Schema remains `../protocol/schemas/capability-manifest.schema.json`. The SDK validator is a convenience implementation and must remain semantically aligned with that schema.

## Examples

- `examples/media-intake.capability.json` — KYN-W01 with local Notes/files data and allowlisted resolver access.
- `examples/local-file-sort.capability.json` — local-only file organization with no network access.

## Extension contract

A Kyntral extension declares:

- stable publisher + capability identifier;
- required K0–K4 risk;
- execution location;
- device-data categories;
- network access and exact allowlist when applicable;
- side effects;
- approved destination identifiers where applicable.

A manifest is descriptive policy input. It **never** creates a capability grant.

```text
manifest != registry certification != user grant != device authorization
```

Extensions must never request a generic arbitrary-shell, arbitrary-URL, unrestricted Shortcut, or equivalent catch-all capability.

## Package status

The package remains `private: true` during the v0.1 RC so the project does not accidentally publish an npm package before release provenance, package signing, and final API review are complete.

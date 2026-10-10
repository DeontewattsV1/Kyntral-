# Kyntral Builder

Kyntral Builder is the visual authoring surface for **permissioned capability declarations**.

**v0.1 RC status:** browser prototype implemented in this directory. It generates Capability Manifest v1 JSON; it does not create runtime grants or execute workflows.

Open `index.html` in a browser to use the prototype.

## Design rule

```text
workflow/capability declaration
      !=
registry certification
      !=
capability grant
      !=
device authorization
```

The current prototype lets a developer select:

- capability ID and module version;
- publisher identity;
- K0–K4 risk class;
- execution location and background declaration;
- device-data categories;
- network allowlist;
- side effects;
- destination IDs.

It emits a `kyntral.capability.v1` manifest compatible with the public schema/SDK surface.

## Privacy boundary

The Builder should describe authority requirements, not ingest user workflow payloads. Local selectors, Notes contents, URLs, filenames, media bytes, and other private execution inputs should stay on-device whenever possible.

## RC limitations

The prototype does not yet provide:

- graphical node/edge workflow editing;
- registry publishing;
- live conformance execution in-browser;
- user grant creation;
- production account synchronization.

Those are post-prototype features and must not be implied by the v0.1 RC UI.

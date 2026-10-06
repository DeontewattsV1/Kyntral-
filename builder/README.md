# Kyntral Builder

Kyntral Builder is the planned visual authoring surface for **permissioned local workflows**.

**Status:** design contract only; no production Builder implementation is present yet.

## Design rule

A Builder workflow declares capabilities and constraints. It does not grant itself authority.

```text
workflow definition
      !=
capability grant
      !=
device authorization
```

## Example

```yaml
version: kyntral.workflow.v1
name: Media Intake
execution:
  location: device
  background: allowed
capabilities:
  - notes.read.scoped
  - network.media.resolve
  - files.write.scoped
privacy:
  cloudContentAccess: none
limits:
  maxItems: 25
destination:
  id: dest_archive
```

The cloud-facing representation should contain only the opaque workflow identifier and authorization metadata. Local selectors, filenames, Note contents, URLs, media bytes, and other private payloads stay on-device.

## Planned surfaces

- workflow graph editor
- capability/risk inspector
- standing-grant editor
- local test runner
- privacy-boundary preview
- manifest export/import
- conformance report

Official Builder core is part of Kyntral Core and follows the repository license map.

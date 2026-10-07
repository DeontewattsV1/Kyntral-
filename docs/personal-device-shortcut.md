# Link a personal device with the Kyntral Shortcut

The shared Kyntral Shortcut is available here:

**https://www.icloud.com/shortcuts/effa6cac2e9b4702bed9128a8749e1f8**

## What the Shortcut is for

The Shortcut is the user-facing bridge between Apple Shortcuts/Notes and the Kyntral local runtime. It lets a user bring private workflow inputs onto their own device without requiring the Kyntral control plane to receive Notes contents, source URLs, media bytes, filenames, or other private workflow payloads.

## Recommended onboarding

```text
1. User opens the iCloud Shortcut link.
2. User installs the Shortcut on their own iPhone or iPad.
3. User opens the Kyntral app on that same device.
4. Kyntral creates/loads the device-local signing and key-agreement identities.
5. User completes Kyntral's cryptographic device pairing flow.
6. User configures KYN-W01:
   - Kyntral scope ID
   - approved Cobalt-compatible HTTPS resolver
   - local/iCloud destination
   - exact standing grant for wf_media_intake / workflow.execute
7. Shortcut extracts or receives media links and stages them locally.
8. The Kyntral control plane may queue only an opaque, signed ActionEnvelope.
9. The device verifies that action, reads the locally staged URLs, executes KYN-W01, signs the receipt, and returns only the content-free verification result.
```

## Security boundary

The Shortcut link itself is **not**:

- a device-pairing credential;
- an OAuth access token;
- a Kyntral capability grant;
- authorization for arbitrary Shortcuts;
- authorization for arbitrary URLs;
- authorization for arbitrary device control.

Kyntral still requires:

```text
authenticated principal
AND paired device
AND exact scope
AND exact workflow
AND exact capability
AND valid standing/current grant
AND signed unexpired action
AND replay protection
```

Only then may the device execute.

## Privacy boundary

Private workflow inputs should stay on the user's device whenever possible.

For KYN-W01:

```text
Shortcut / Notes
      ↓
local Kyntral inbox
      ↓
local resolver / dedupe / iCloud output

Kyntral Cloud receives:
deviceId
scopeId
workflowId
capability
risk
action/receipt cryptographic metadata

Kyntral Cloud does not need:
Note text
source URLs
media bytes
clipboard contents
destination filenames
```

## Shared-link lifecycle

If the Shortcut changes materially, treat the shared-link version as a release artifact. Re-test the onboarding path and update this document if a new iCloud Shortcut link replaces the current one.

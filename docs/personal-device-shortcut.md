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


## Link the personal device through the User API

The current iOS RC exposes pairing controls in the Kyntral app. The shared Shortcut does **not** carry the User API token.

On the same iPhone or iPad:

1. Install the shared Shortcut.
2. Open Kyntral.
3. In **Personal Device API**, enter the production Kyntral HTTPS API base URL.
4. Obtain an OAuth access token through the approved Kyntral authorization flow.
5. Enter that token into the app session.
6. Tap **Pair this device**. Kyntral generates/loads the local signing and key-agreement identities, obtains a one-time pairing challenge, signs it locally, and pins the server action-signing key returned by the pairing response.
7. Use **Check** to verify paired status.
8. Configure KYN-W01 and its exact local standing grant.
9. The Shortcut stages media inputs locally.
10. Use **Run next** (or the later background delivery path) to retrieve and execute an authorized signed ActionEnvelope.
11. Use **Revoke this device** to disable future authorization for that paired device.

The iOS device client needs narrowly separated scopes appropriate to the operation:

```text
kyntral.pair
kyntral.read
kyntral.device.execute
kyntral.receipt.submit
kyntral.revoke
```

The AI/MCP client does not receive these merely because the iOS device has them. MCP proposal scopes and device execution scopes remain distinct.

## Token boundary

The OAuth token is intentionally **not** embedded in:

- the iCloud Shortcut;
- a Note;
- a KYN-W01 workflow definition;
- the cloud ActionEnvelope;
- the local URL inbox.

The current RC UI keeps the token in app-session state only. A production iOS authentication UX should obtain and refresh tokens through the final OAuth provider rather than asking users to manually paste long-lived bearer tokens.

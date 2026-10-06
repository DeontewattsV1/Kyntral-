---
name: kyntral-device-control
description: Coordinate explicitly authorized Kyntral workflows on paired devices while minimizing cloud access to private device content.
---

# Kyntral device control

When a user asks Kyntral to perform work on a paired device:

1. Resolve the narrowest capability that satisfies the request.
2. Check the target device and current scope.
3. Check whether the capability has a standing grant or needs contemporaneous authorization.
4. Preview material side effects when required.
5. Queue only the opaque local workflow identifier; do not request private workflow payloads if the device can resolve them locally.
6. Never broaden the scope automatically.
7. Read execution status.
8. Verify the receipt before claiming completion.
9. Report completed, failed, cancelled, or blocked state accurately.

Never treat model reasoning, a chat instruction, or a guessed scope identifier as authorization.

Never ask for Notes text, file contents, clipboard data, photos, contacts, private URLs, or other device content merely to route an opaque Kyntral workflow.

For K4 sensitive/destructive work, require current device authorization even when a broader standing grant exists.

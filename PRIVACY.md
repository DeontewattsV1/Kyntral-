# Kyntral privacy model

Kyntral is designed around **capabilities without custody**.

## Default data boundary

The Kyntral control plane should store only what is necessary to authenticate,
authorize, route, and verify an action:

- opaque account identifier
- device identifier and public keys
- scope/capability identifiers
- authorization policy metadata
- opaque workflow identifier
- job state and expiration
- minimal security/audit events
- receipt hash/signature metadata

The control plane should not receive these by default:

- Notes contents or note titles
- Photos or media bytes
- clipboard contents
- contacts
- private prompt/conversation history
- file contents or filenames
- raw URLs contained in private workflows
- local workflow secrets

## Local execution

When a workflow can operate on-device, an AI client requests an opaque
`workflowId`. The iPhone resolves that identifier against local configuration,
uses only locally granted data access, performs the work, and returns a minimal
signed receipt.

## Diagnostics

Diagnostics should be opt-in and content-free. Useful diagnostics include app
version, OS version, capability type, coarse failure code, and crash category.

## Training and advertising

The intended Kyntral service does not need private workflow content for model
training or advertising. Product analytics must never be used as a reason to
collect payloads the protocol does not otherwise require.

## Privacy invariant

A release fails conformance if the cloud job or cloud receipt schema grows a
field capable of carrying private workflow payloads without an approved protocol
change and privacy review.

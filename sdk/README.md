# Kyntral SDK

The Kyntral SDK surface is intended to make **capability compatibility open and portable** while keeping production authority explicit.

**License target:** Apache-2.0 for public protocol-facing SDK interfaces and examples.

## Extension contract

A Kyntral extension should declare:

- stable publisher + capability identifier
- required risk class
- local/network execution boundary
- data-access categories
- allowed destinations/domains when applicable
- whether background execution is supported
- conformance status

Extensions must never request a generic arbitrary-shell, arbitrary-URL, or unrestricted Shortcut capability.

## Planned packages

```text
@kyntral/protocol
@kyntral/sdk
KyntralSwift
```

The protocol schemas in `../protocol/schemas/` are the current source of truth for serialized objects.

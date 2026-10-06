# Kyntral Registry

The Kyntral Registry is the planned trust and discovery layer for third-party capability modules.

**Status:** architecture only. No public registry service exists yet.

A registry entry is expected to bind:

```text
publisher
capability ID
version
source repository
declared risk
network policy
privacy declaration
signature
conformance result
certification tier
```

Proposed trust tiers:

1. Experimental
2. Community
3. Verified
4. Kyntral Certified
5. Core

Registry listing is not the same as runtime authorization. A user/device grant is still required before execution.

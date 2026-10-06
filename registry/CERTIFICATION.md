# Kyntral Registry certification policy v0.1

SPDX-License-Identifier: Apache-2.0

Registry status describes review evidence. It never grants runtime authorization.

## Tiers

| Tier | Meaning | Minimum evidence |
| --- | --- | --- |
| Experimental | Unreviewed development module | syntactically valid Capability Manifest |
| Community | Community-published module | source repository, publisher identity, declared risk/network/data boundaries |
| Verified | Independently reproducible module | conformance pass, pinned source version, build provenance, no unresolved critical security finding |
| Kyntral Certified | Canonical Kyntral review | Verified requirements plus privacy/security review, side-effect review, compatibility test, signed release provenance |
| Core | Shipped by canonical Kyntral release | Certified requirements plus canonical ownership/release pipeline |

## Review triggers

A new review is required when a module changes any of:

- capability identifier or publisher;
- declared K0–K4 risk;
- device-data category;
- network domain allowlist;
- execution location or background-execution status;
- external side effects;
- cryptographic or authorization behavior.

## Non-equivalence rule

```text
registry listing != capability grant != device authorization
```

A listed or certified extension cannot execute until the user/device authorization path independently permits the exact capability.

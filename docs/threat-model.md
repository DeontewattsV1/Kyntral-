# Threat model — pre-alpha

## Assets

- user authorization state
- device private keys
- standing grants
- workflow definitions
- user content on device
- execution receipts
- canonical protocol/registry trust

## Adversaries

- malicious or compromised model/client
- prompt injection
- stolen bearer/session token
- malicious extension
- replay attacker
- compromised Kyntral cloud component
- SSRF/network pivot through an adapter
- supply-chain compromise
- misleading UI that broadens consent

## Primary mitigations

- narrow typed capabilities
- server-side authorization
- device-bound identity
- expiring actions
- nonces/idempotency
- separate signing/key-agreement keys
- local content handling
- content-free cloud job schema
- declared extension permissions
- receipt/action binding
- branch protection + CI + signed releases

## Explicit non-goal

Kyntral cannot make an already-compromised iPhone or maliciously modified local runtime trustworthy. Device integrity signals may improve assurance later but do not replace authorization semantics.

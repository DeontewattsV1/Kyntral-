---
name: kyntral-release-readiness
description: Evaluate whether Kyntral is ready for RC, TestFlight, production MCP deployment, OpenAI/Grok integration testing, Product Hunt, or public launch.
---

# Kyntral release readiness

Evaluate release readiness as evidence-backed gates, not as a marketing checklist.

Required gates include:

- frozen canonical signing rules and normative cryptographic vectors;
- separate device signing and key-agreement identities;
- one-time pairing, nonce/idempotency replay protection, expiration/skew rules, and revocation;
- exact action-to-receipt cryptographic binding;
- release-blocking PRIV-* cloud leakage tests;
- durable content-free control-plane storage;
- OAuth resource binding and server-side per-operation scope enforcement;
- reviewable write-tool annotations and side effects;
- stable HTTPS Streamable HTTP MCP deployment;
- a buildable iOS application with local keys, pairing, standing grants, App Intents, dedupe, KYN-W01, action verification, and signed receipts;
- OpenAI and Grok/xAI tests against the same remote MCP surface;
- Capability Manifest v1 and extension/registry conformance;
- active repository protection, required CI/CODEOWNERS review, dependency audit, SBOM, and secret scanning;
- qualified legal review of custom BUSL grant, CLA, and trademark policy;
- privacy policy, terms, support path, landing page, installable product, demo assets, and launch evidence.

Never schedule Product Hunt merely because documentation, prototypes, or scaffolding exist.

Return:

1. verified completed gates;
2. unresolved blockers;
3. the next narrow implementation boundary;
4. claims that must remain explicitly unverified.

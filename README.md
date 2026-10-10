# Kyntral

> **AI coordinates. You control.**

Kyntral is a privacy-first permission layer between AI systems and user-owned devices. An AI can request a narrowly scoped capability; Kyntral verifies identity, device, scope, and authorization; the paired device executes under local operating-system controls; and the device returns a verifiable receipt.

**Status:** **v0.1 release candidate implementation.** Core protocol, durable control plane, iOS device authority, KYN-W01, SDK/Builder prototypes, and release conformance exist. Production MCP deployment, live provider interoperability, active repository protections, TestFlight/physical-device evidence, legal approval, and launch assets remain release gates.

## Core invariants

```text
AI proposal != authorization != execution != verification
```

```text
Kyntral Cloud should not need user content to authorize device work.
```

The intended control plane handles opaque account/device/scope/capability/job metadata and receipt hashes. Notes, photos, clipboard contents, file contents, private prompts, media bytes, and workflow payloads stay on-device whenever local execution is possible.

## Product surfaces

- **Kyntral Plugin** — portable OpenAI plugin package with skills and MCP configuration.
- **Kyntral MCP** — model-neutral capability control plane.
- **Kyntral iOS** — Swift/App Intents runtime for Siri and Shortcuts.
- **Kyntral Builder** — browser RC prototype for authoring Capability Manifest v1 declarations.
- **Kyntral Protocol** — schemas, signing rules, receipts, and conformance vectors.
- **Kyntral SDK / Registry** — Apache-2.0 RC capability-manifest SDK plus prototype registry/certification model.

## Architecture

```text
ChatGPT / Grok / MCP client
           |
           | capability request
           v
+----------------------------+
|         Kyntral MCP        |
| identity / policy / scope  |
+-------------+--------------+
              |
              | opaque authorized job
              v
+----------------------------+
|       Paired iPhone        |
| keys + local policy        |
| App Intents + Shortcuts    |
+-------------+--------------+
              |
              | local execution
              v
        user-owned data
              |
              | signed receipt
              v
+----------------------------+
| verification / audit hash  |
+----------------------------+
```

## Authorization classes

| Class | Meaning | Default |
| --- | --- | --- |
| K0 | Read-only status/health | automatic |
| K1 | Reversible local action | standing grant allowed |
| K2 | Approved network interaction | standing grant allowed |
| K3 | External write | bounded standing grant or approval |
| K4 | Sensitive/destructive action | contemporaneous device authorization |

“Unattended” means **pre-authorized and policy-bounded**, not unrestricted autonomy.

## Repository layout

```text
protocol/       public schemas and invariants
control-plane/  durable MCP + OAuth authorization/resource service
ios/            buildable iOS/App Intents device runtime
skills/         agent workflow guidance
conformance/    release-blocking tests
docs/           architecture, threat model, integrations
brand/          Kyntral brand system
launch/         Product Hunt/release planning
```

## Personal-device Shortcut

Install the official shared Kyntral Shortcut on the iPhone or iPad you want to use with Kyntral:

**[Install Kyntral Shortcut](https://www.icloud.com/shortcuts/effa6cac2e9b4702bed9128a8749e1f8)**

Recommended onboarding flow:

```text
Install shared Shortcut
-> open Kyntral on the personal device
-> pair the device cryptographically
-> configure KYN-W01 locally
-> grant the exact local workflow
-> Shortcut stages private media links locally
-> signed Kyntral actions may execute that authorized workflow
```

The iCloud Shortcut link is a distribution/onboarding mechanism only. Installing it does **not** pair a device, grant Kyntral capabilities, or authorize arbitrary device control. Pairing and authorization remain separate Kyntral security operations.

## First conformance workflow

**KYN-W01 — Media Intake**

```text
AI requests opaque workflow
-> Kyntral authorizes scope
-> paired iPhone reads approved local source
-> device canonicalizes + deduplicates
-> device performs approved work
-> device signs receipt
-> cloud verifies receipt without receiving private payload
```

Provider-specific adapters must comply with provider terms and must never be used to bypass access controls.

## Development

```bash
npm install
npm run typecheck
npm test
npm run conformance
```

The TypeScript control plane targets the current MCP TypeScript SDK line. The iOS directory contains a committed Xcode project with device identity, pairing, local policy, App Intents, KYN-W01, action verification, device request proofs, dedupe, retry-safe receipt journaling, and XCTest coverage.

## RC landing preview

A public v0.1 RC landing preview is deployed at:

**https://kyntral-rc.vercel.app/**

This is a product/onboarding preview only. It is **not** the production Kyntral MCP/API endpoint and is not evidence that the external release gates are complete.

## Plugin status

The portable OpenAI plugin manifest is included. `mcp.json` intentionally points to the reserved `.invalid` domain until a production HTTPS MCP endpoint exists. Do not submit the plugin publicly before replacing that URL and completing the release gates.

## Licensing

Kyntral uses a mixed-license model:

- protocol schemas, public SDK-facing types/examples, and conformance vectors: **Apache-2.0**
- Kyntral Core/control-plane and official Builder core: **Business Source License 1.1**
- production credentials, signing material, abuse controls, and private infrastructure: not distributed
- Kyntral name, marks, and visual identity: governed separately by `TRADEMARKS.md`

See `LICENSE` and `LICENSES/`.

## Governance

Community issues, PRs, capability modules, and Kyntral Enhancement Proposals are welcome. Canonical protocol releases, registry certification, production signing, brand use, and final merges remain subject to Kyntral governance.

## Independence

Kyntral is an independent project. It is not affiliated with, sponsored by, or endorsed by Apple Inc., OpenAI, xAI, or X Corp. Names are used only to describe interoperability.

---

Initial architecture and repository stewardship: **Deonte Watts**.

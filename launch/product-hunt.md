# Product Hunt launch plan

## Product

**Kyntral**

**Tagline:** The permission layer between AI and your devices.

## Launch claim

Kyntral lets AI systems request narrowly scoped device capabilities without receiving unrestricted control or custody of private device content.

Do not use "world's first" until a documented prior-art/product search supports the claim.

## Launch gate

Do not schedule the public Product Hunt launch until all are true:

- stable landing page
- usable iOS/TestFlight build
- production HTTPS MCP endpoint
- authentication + authorization implemented
- OpenAI plugin tested
- Grok/remote-MCP integration tested
- at least three real workflows
- privacy and security documentation
- onboarding/support path
- conformance suite green
- demo video and gallery assets
- release candidate frozen

## Gallery story

1. **Hero** — Kyntral / AI coordinates. You control.
2. **Privacy** — private payload stays on-device.
3. **Builder** — workflow + policy canvas.
4. **Cross-agent** — ChatGPT, Grok, future MCP clients -> Kyntral -> device.
5. **Receipt** — authorized, device verified, completed, receipt signed.

## Maker post draft

Meet **Kyntral** — the permission layer between AI and your devices.

AI assistants are becoming capable of doing real work, but giving an AI unrestricted access to a personal device is the wrong security model.

Kyntral takes a different approach. An AI requests a capability. Kyntral verifies the user, paired device, scope, and authorization policy. The device performs the approved action locally when possible and returns a verifiable receipt.

The core rule is simple:

**AI proposes. You authorize. Your device executes. Kyntral verifies.**

We are building Kyntral around local-first privacy, narrow capabilities, revocable standing grants, MCP interoperability, and a developer extension model.

Feedback on the permission model, developer APIs, and useful device workflows is especially welcome.

# Architecture

## Trust decomposition

Kyntral intentionally separates four authorities:

```text
planner        -> proposes
policy engine  -> authorizes
device runtime -> executes
receipt verifier -> verifies
```

No layer may silently inherit authority from the previous layer.

## Content plane vs control plane

**Control plane:** opaque identifiers, policy, device public identity, job lifecycle, receipt verification.

**Content plane:** user Notes, files, clipboard, media, local workflow parameters, and other private payloads.

The content plane should remain on-device unless the user explicitly installs a capability whose declared behavior requires an external processor.

## Model neutrality

Kyntral's internal action model uses `AgentAction`/MCP semantics rather than provider-specific ChatGPT or Grok action types. Provider adapters must not alter authorization semantics.

## Project scoping

Until an AI host exposes a trusted stable project identifier suitable for authorization, Kyntral project scopes remain Kyntral-owned authorization objects. Host conversation/session metadata must not be treated as proof of authorization.

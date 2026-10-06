# Contributing to Kyntral

Thank you for helping improve Kyntral.

## Before writing code

1. Read `AGENTS.md`, `GOVERNANCE.md`, `PRIVACY.md`, and `SECURITY.md`.
2. For protocol/security/privacy changes, open a design issue or KEP first.
3. Keep the change narrowly scoped.
4. Never include real user data or credentials in fixtures.

## Local checks

```bash
npm install
npm run typecheck
npm test
npm run conformance
```

## Pull requests

A good PR explains:

- problem and intended behavior
- affected capability/risk class
- privacy impact
- authorization impact
- tests added/changed
- backward-compatibility impact
- licensing area touched

## Contributor licensing

The project intends to use a contributor agreement that preserves contributor
authorship while granting the canonical project sufficient rights to distribute,
commercialize, and relicense contributed material where required by the mixed
licensing model.

**Until that workflow is finalized, maintainers should not merge external code contributions.**
Design discussion and review are welcome.

## Developer extensions

Third-party extensions should prefer portable capability manifests and MCP tools
over changes to Kyntral Core. Extensions must accurately declare network access,
side effects, risk class, and required device data.

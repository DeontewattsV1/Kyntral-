# Contributor license workflow — v0.1 RC

Kyntral's contributor workflow is deliberately fail-closed until the legal text is approved.

## Current state

- `CLA-DRAFT.md` describes the intended copyright/patent/relicensing structure.
- External code contributions MUST NOT be merged while that document is marked non-operative.
- Issues, design proposals, review comments, test reports, and other non-code feedback may be accepted under the normal repository contribution process.

## Activation gate

The code-contribution workflow becomes active only after all of the following:

1. qualified counsel approves the final individual/corporate CLA language;
2. the canonical `CLA.md` replaces `CLA-DRAFT.md`;
3. the repository records assent through an auditable GitHub/CLA service or signed agreement workflow;
4. CI or merge policy exposes the CLA status to reviewers;
5. `CONTRIBUTING.md` is updated to name the active workflow;
6. governance records the activation in a release/KEP decision.

## Merge rule

Until activation:

```text
external code contribution
        ↓
CLA not operative
        ↓
DO NOT MERGE
```

After activation:

```text
external code contribution
        ↓
authorship/right-to-submit checks
        ↓
recorded CLA assent
        ↓
CI + security/conformance review
        ↓
CODEOWNERS / governance review
        ↓
eligible for merge
```

This workflow keeps the repository technically ready for a CLA while avoiding the false claim that an unreviewed draft already creates a binding contributor agreement.

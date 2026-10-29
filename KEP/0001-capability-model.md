# KEP-0001 — Capability and risk model

Status: Draft  
Author: Deonte Watts  
Date: 2026-10-06

## Decision

Kyntral capabilities are narrow, explicitly declared operations assigned one of five risk classes: K0 through K4.

## Rationale

A generic device executor collapses proposal, permission, and execution into one unsafe authority. Typed capabilities give users and reviewers a stable surface for understanding what an agent may request.

## Classes

- K0 — read-only status/health
- K1 — reversible local work
- K2 — approved network interaction
- K3 — external writes
- K4 — destructive/sensitive operations

Standing authorization may cover K1/K2 and bounded K3 capabilities. K4 requires contemporaneous device authorization by default.

## Non-goal

Risk class does not imply that every capability in the class is equally dangerous. Individual manifests can impose stricter policy.

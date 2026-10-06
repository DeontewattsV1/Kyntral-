# Kyntral iOS scaffold

SPDX-License-Identifier: BUSL-1.1

Kyntral iOS is the intended local execution authority.

## Modules

- `KyntralCore` — capability/risk/execution contracts.
- `KyntralIntents` — App Intents surfaced to Siri/Shortcuts.
- future `KyntralCrypto` — device signing and key agreement.
- future `KyntralStorage` — local workflow definitions and dedupe ledger.

## Device boundary

The production application must generate device private keys locally and must never transmit those private keys to Kyntral Cloud.

## Xcode setup

Create an iOS SwiftUI application, add the source files in this directory to the application target, enable the entitlements actually required by each capability, and verify every App Intent on a physical device before release.

Do not request broad entitlements preemptively.

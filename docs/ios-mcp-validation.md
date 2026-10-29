# iOS and MCP validation boundary

The Xcode target uses one implementation per type. `DeviceAuthority.swift`,
`LocalWorkflowRuntime.swift`, and `MediaIntake.swift` were overlapping consolidated
copies and are removed. The target now compiles the split core files, the device
client and local inbox, all four App Intents files, and all six XCTest files.
`DeviceKeyManager.swift` retains the previously compiled CryptoKit/Keychain
implementation, including its service, account names, and accessibility policy,
so reconciliation preserves existing device keys rather than changing custody.

The protocol action/receipt types, action signature verifier, and replay ledger in
`ReceiptSigner.swift` are restored from repository commit
`da515845a2f05df940a5f27069cc461476435115`. The existing excluded tests and device
client already depended on those definitions. The current wire format uses
`authorizationProof`, `counts`, and `deviceProof`, matching the protocol schemas.
Runtime grant checks also pass the workflow risk explicitly. Restoration is source
reconciliation, not independent security signoff or a new protocol version.

## Evidence generation

CI and iOS explicitly check out the pull request head SHA (or push SHA), and record
`git rev-parse HEAD` in their artifacts. This avoids confusing a PR merge-test ref
with the source revision actually exercised. The macOS iOS job runs for every PR
and main push, including dependency-only changes.

`python3 scripts/verify-ios-evidence.py` fails if any Swift source is missing,
duplicated, or placed in the wrong target. It inventories all test methods in the
six XCTest files. After `xcodebuild test`, it checks the machine-readable result
bundle output and requires each expected test to pass exactly once. Missing,
skipped, failed, and duplicate results fail the gate; the gate's own negative
checks run in CI. The retained iOS artifact contains the `.xcresult`, full test
log, simulator/toolchain identifiers, expected test inventory, and source SHA.

The focused MCP suite runs the installed SDK through the real in-process `/mcp`
HTTP handler with fixture OAuth introspection. It covers legacy initialization,
modern stateless transport, tool schemas and invocation, successful signed-action
queueing, scope denial, absent/mismatched grants, revoked devices, ownership,
issuer/audience binding, malformed input, and invalid credentials. It makes no
live provider or production OAuth claim. CI retains JUnit reports, focused logs,
the generated dependency lock, CycloneDX SBOM, and source SHA for 30 days.

## Release limits

Passing this boundary does not establish rollback-resistant replay-state custody,
crash-safe exactly-once side effects, complete resolver network restrictions,
hardware key isolation, physical-device/TestFlight readiness, a deployed HTTPS
MCP/OAuth service, OpenAI/xAI interoperability, active repository protection,
legal review, or independent security approval. Those release gates remain open
until separately supported by evidence. See `release-gates.md`.

Provenance: repository source reconciliation for Deonté O'dell Watts / GoodShyt Group Inc., 2026-10-28. Existing license assignments remain applicable. No scientific novelty claim.

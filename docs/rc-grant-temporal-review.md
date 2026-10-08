# RC grant temporal integrity review

Base: `20a6a6047f19e793e03e254304cec1c59d4ac47a`.
Review date: 2026-10-08 UTC. Implementation and regression tests: AI-assisted.

## Verified narrow boundary

Persistent authorization now returns `Unknown` for invalid evaluation clocks,
invalid issue/expiry timestamps, future issue times, and nonpositive grant
intervals. Only `Allowed` permits execution. Explicit denial and revocation
retain precedence. Valid unbounded grants remain supported. Existing expiry
comparison semantics are preserved; this change adds no clock-skew allowance.

The original evaluator returned `Allowed` in four regression cases: malformed
expiry, malformed issue time, invalid evaluation clock, and future issue time.
The reversed/empty interval cases previously returned `Expired` and now return
`Unknown`, because their temporal evidence is malformed.

Verification: typecheck passes; 54 unit tests and 53 conformance tests pass;
dependency audit reports zero vulnerabilities. Running the new unit regression
cases against the original evaluator fails six cases, establishing that the
tests distinguish the fix from the baseline. Persistent SQLite conformance also
checks that malformed expiry cannot override explicit denial or revocation.

Adversarial review: valid unbounded grants still authorize; malformed grants
fail closed; denial/revocation remain distinct; all comparisons use epoch
milliseconds. No user payload, new scope, signing format, provider exception,
or endpoint replacement is introduced. A separate security-focused review is
still required before release under AGENTS.md.

## Unresolved release gates

This review does not establish production HTTPS MCP deployment, production OAuth,
live OpenAI/Grok interoperability, physical-device/TestFlight validation, active
repository protection, secret-scan completion, or legal approval. The reserved
`.invalid` endpoint remains reserved. Product Hunt remains unscheduled.

## Next narrow boundary

Review fail-closed runtime timestamp handling across signed action, pairing,
device-request, and nonce paths, including invalid clocks and persisted temporal
metadata. Freeze interoperable vectors only after the same semantics are checked
against the iOS implementation. Do not infer execution or verification from an
authorization decision.

## Timestamp boundary continuation

Shared temporal validation now rejects nonfinite evaluation clocks and invalid
skew/lifetime policy values. Nonce consumption rejects malformed expiries and
invalid clocks before writing. Pairing challenge consumption uses the same
validated five-minute lifetime and inclusive 60-second skew as proof validation;
pairing nonce retention includes that skew. The atomic consumed-state update
continues to permit only one consumer.

Additional evidence: typecheck passes, 62 unit tests and 54 conformance tests
pass. Pairing tests cover issuance, raw expiry, and expiry plus skew, with replay
rejection at each point. Invalid-clock and one-millisecond-past-skew failures do
not consume challenges. The frozen signed device-request vector fails closed
with an invalid clock, accepts exactly at expiry plus 30 seconds, and rejects
replay and one millisecond beyond skew. Nonce tests verify rejected malformed
inputs leave the nonce available for a subsequent valid consumption.

Static iOS review: action time comparisons use rejecting guards, and replay
retention uses expiry plus accepted skew with inclusive retention. This is source
inspection, not Xcode or physical-device execution evidence.

Remaining timestamp questions: JavaScript Date.parse accepts some non-RFC3339
inputs; strict interoperable timestamp syntax and calendar validation need a
separate decision and shared vectors. Action polling uses raw-expiry SQL string
comparisons, potentially stricter than device action validation and sensitive to
noncanonical persisted times. Pairing challenge/nonce consumption are separate
writes; crash-safe transaction handling remains a separate review boundary.

## Strict parsing, polling, and atomic pairing proposal

Continuation from main a4df7c5. Shared parsing now validates calendar dates and
requires a proposed millisecond-resolution RFC3339 profile: uppercase T/Z,
explicit known timezone, zero to three fractional digits, and no leap seconds.
Unknown offset -00:00 and greater-than-millisecond precision are rejected. This
is an RC protocol-profile proposal requiring security/interoperability review,
not a claim of support for every RFC3339 representation. Grant evaluation and
nonce persistence use the same parser.

Action polling compares parsed epoch times and validates the signed action's
full lifetime/skew window before changing state. A job expiry must represent the
same instant as its action expiry. Invalid/expired candidates are skipped.
Pairing challenge consumption, nonce consumption, and device persistence are now
one BEGIN IMMEDIATE transaction, including a revocation recheck under the write
lock. An injected malformed device write proves challenge and nonce rollback;
retry succeeds once and replay fails.

Local evidence: typecheck, 70 unit tests, and 54 conformance tests pass. Tests
cover invalid dates, leap dates, equivalent offsets, action delivery at the skew
endpoint and rejection one millisecond later, and pairing failure rollback.
The hosted iOS workflow now triggers on shared timestamp/protocol/conformance
changes. Xcode is unavailable in this Linux runtime; simulator and physical-device
results must remain unverified until actual evidence is available. Swift parser
alignment with the proposed strict profile remains an interoperability blocker.

# Red-team remediation — 2026-09-16

Branch: `fix/red-team-2026-09-15`.

This addresses the five findings in `RED_TEAM_REPORT_2026-09-15.md`.
It does not supersede the production gates in `SECURITY.md`.

| Finding | Change | Regression coverage |
| --- | --- | --- |
| RT-01 | Shared admission caps (256 global, 8 per canonical peer), absolute first-message/idle deadlines, bounded writes, bounded WebSocket outbound queues, fallible worker spawning and resource cleanup | TCP cap/refusal/re-admission, idle/partial prefixes/partial bodies, stalled WebSocket upgrade, idle WebSocket, non-reading peer write deadline |
| RT-02 | Shared pre-recognition peer budget, charged on admission, nonempty reads and message attempts; three-invalid-message connection limit; existing semantic limiter retained | Shared budget exhaustion/window/cap tests; malformed TCP and WebSocket closure |
| RT-03 | Reverted new v1 allocation lifetime to 60–600 seconds in both schema and mailbox constructor | Lifetime boundary, encoding/recognition and expiry tests |
| RT-04 | Pre-deserialization outer caps on public wire and credential/v2 CBOR decoding, with smaller limits for smaller formats | One-octet-oversize invalid CBOR returns `Size` before parsing; existing maximum-size and round-trip suites |
| RT-05 | Exact explicit WebSocket origin allowlist; missing origins refused by default; explicit missing-origin opt-in for separately authenticated native clients | Allowed, hostile, null, alternate-port, case-variant and missing origins |

## Compatibility and rollout

- WebSocket operators must configure `--allow-origin` for browser clients or
  explicitly enable `--allow-missing-origin` for native clients behind an
  authenticated edge. Supplied origins are still checked with that flag enabled.
- Clients must send application protocol pings while waiting for human input;
  WebSocket control pings do not extend the 30-second application idle deadline.
- v1 requests above 600 seconds now fail recognition/construction. Credential/v2
  retains its fixed 900-second lease. Persisted mailboxes retain original expiry:
  follow the operator guide's emergency-close or expiry-wait migration before
  allocation against a store created by the 24-hour implementation.
- Limits are conservative reference-shell constants. The proxy must also limit
  actual clients because the shells use the immediate socket peer identity.
- The synthetic-profile source hash pins were updated for these shared relay
  changes. Historical evidence bundles were left unchanged.

## Verification

- Full locked all-target/all-feature test suite: passed with local socket binding
  allowed, including the existing independent endpoint interoperability test.
- Final transport regression suite: passed after write-deadline hardening.
- Formatting, diff whitespace checks and all-target/all-feature Clippy with
  warnings denied: passed.
- Bounded fuzz campaign: 10,000 wire-recognition, 5,000 mailbox-transition and
  1,000 channel-receiver runs completed without a finding.
- Existing seven mutation cases: all seven killed, checked against a temporary
  snapshot of the remediation sources rather than the unchanged branch HEAD.
- `cargo-deny` is not installed, so its dependency policy gate was not run.
  Dependencies and lockfiles were not changed.

Independent security review and production-scale load testing remain outstanding.
The bounded local tests and fuzz campaign do not substitute for those gates.

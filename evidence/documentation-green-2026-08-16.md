# Documentation implementation evidence

- Date: 2026-08-16
- Component: `documentation`
- Commands:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --doc --all-features`
  - `cargo test --examples --all-features`
  - `cargo test --all-targets --all-features`
  - `cargo doc --no-deps --all-features`

## Result

The README now begins with the cross-application user experience and states the
non-production gate. It explains the reusable layering, optional relay, profile
extension boundary, generic cbcl-rs dependency, repository contents, build
gate, and reference-relay status.

The API guide records the shell/library trust boundary, module ownership,
canonical-byte boundary, CPace application wrapper, endpoint lifecycle,
profile contract, relay embedding contract, and terminal-error handling. The
application tutorial follows invitation creation through durable consumption,
CPace, Finished, projected intent, explicit consent, payload verification, and
mailbox closure. It includes the exact 22-bit agent carrier statement and does
not present deterministic fixture entropy as production randomness.

The operator guide records the private-listener wire, key-file constraints,
disabled-by-default allocation, conformance-only flag, fixed caps, safe logs,
failure/recovery semantics, metadata exposure, and multi-operator model. The
security guide records claims, exclusions, endpoint and relay trust boundaries,
entropy and erasure obligations, and every mandatory production gate.

The `derive_pairing_context` example compiles under the all-feature target gate.
Rustdoc builds successfully, the full all-feature suite remains green, and all
four local README documentation links resolve to repository files.

## Scope boundary

These documents describe the current low-level conformance API. They do not
create production authority, claim API stability, or close TEST-016, TEST-017,
TEST-018, the fresh-context adversarial review, or any application-profile
owner decision.

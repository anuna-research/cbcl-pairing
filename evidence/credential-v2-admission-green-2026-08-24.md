# Credential/v2 admission Green Gate — 2026-08-24

Authority: SPEC-001 TEST-060 and Selfsame IMPL-008
`pairing-v2-admission`.

Red record:
`evidence/credential-v2-admission-red-2026-08-24.md`.

Focused command:

```text
cargo test --test credential_v2_admission
```

Result: seven passed, zero failed.

Repository command:

```text
cargo test --all-features
```

Result: every unit, integration, process, WebSocket, and documentation test
passed. Credential/v1 tests remained green.

Quality commands:

```text
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Result: all commands passed.

Covered credential/v2 evidence includes the fixed commitment vector, exact
900-second lifetime, wrong and cross-mailbox refusal, single claim, and
commitment erasure. It also includes v1/v2 separation, durable restarts,
redacted bearer diagnostics, and malformed-store startup refusal.

This evidence authorizes no production allocation, release, or deployment.

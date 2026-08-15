# Mailbox core Green Gate

- Date: 2026-08-16
- Scope: pure relay core for `TEST-001`, `TEST-002`, `TEST-003`, `TEST-004`, and `TEST-013`

## Commands and results

`cargo fmt --check` passed.

`cargo clippy --all-targets --all-features -- -D warnings` passed.

`cargo test --test mailbox` passed five tests. The tests demonstrate exact
offline redelivery, immediate ACK deletion, a relay-domain-only snapshot, a
two-member ceiling, third-distinct-claim crowding, immutable retries,
conflicting retry closure, gap rejection without mutation, 16-frame and
69,632-octet bounds, 60–600-second lifetimes, terminal body deletion, and
complete removal at the original expiry.

The recognition and exact-dialect regression suites also passed.

`cargo test --all-targets` passed all of those suites and advanced the
aggregate behavioural Red Gate to `limiter-observability`.

## State boundary

The pure core imports no network, clock, persistence, UI, profile, or grant
module. Random identifiers, token hashes, and time enter as explicit inputs.
State contains locators, membership hashes, sequence/digest metadata, original
expiry, and optional opaque bodies. ACK and every terminal path remove body
bytes; original expiry removes the complete state.

## Residual integration evidence

The mailbox test drives opaque ceremony-shaped bodies through the pure core and
proves the permitted state surface. The complete `TEST-002` instruction to
drive a full cryptographic ceremony through a running relay remains uncredited
until the endpoint and relay-service integration exists. This evidence does
not claim that later gate, interoperability, cryptographic review, or
production approval.

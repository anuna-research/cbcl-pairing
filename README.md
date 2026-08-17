# cbcl-pairing

`cbcl-pairing` provides reusable Rust endpoints and an application-blind relay for consent-gated pairing between two peers.

> **Experimental:** The local implementation supports conformance testing only.
> Production use and production invitation allocation remain prohibited until the named external reviews and owner decisions close.
> See the [security model and production gates](docs/SECURITY.md) for the outstanding evidence.

## Quick Start

Rust 1.85 or newer is required.

From the repository root, run the loopback browser demo:

```sh
cargo run --locked --features relay --example web-demo
```

Open <http://127.0.0.1:8088> and complete the allocator and claimant flow.

The demo exercises CPace, both Finished checks, authenticated CBCL roles, intent recognition, consent, and grant verification in one local process.
It does not provide TLS or a production relay deployment.

## Usage

The crate is not published on crates.io. Add it through a local path or an exact Git revision.

```toml
[dependencies]
cbcl-pairing = { path = "../cbcl-pairing" }
```

For application integration, follow the [application tutorial](docs/TUTORIAL.md).
Implement `ApplicationProfile` and `GrantVerifier`, drive `EndpointReducer`, and perform only the emitted `EndpointEffect` values.

For an isolated relay conformance deployment, follow the [operator guide](docs/OPERATOR.md).
The reference processes keep allocation disabled unless the conformance-only flag enables it explicitly.

Applications with an existing duplex transport can carry canonical `ChannelFrame` bytes directly.
The blind relay is optional.

## Architecture

Applications own user intent, consent, and final grant policy.
Endpoints own canonical recognition, CPace, Finished verification, authenticated roles, and the encrypted ceremony.
The relay owns bounded mailbox state and local abuse control.

```text
+---------+     +------------+      +-------------+      +------------+     +---------+
| App A   | --> | Endpoint A | <==> | Blind relay | <==> | Endpoint B | --> | App B   |
| profile |     | CPace/CBCL |opaque| mailbox     |opaque| CPace/CBCL |     | verifier|
+---------+     +------------+      +-------------+      +------------+     +---------+
```

### End-to-end ceremony

The relay queues frames while either peer is offline. Every frame crossing the relay remains opaque to it.

```text
Allocator                 Blind relay                 Claimant              Person
    |                          |                          |                    |
    |-- Allocate ------------->|                          |                    |
    |<-- mailbox + membership -|                          |                    |
    |==== invitation through an out-of-band carrier =====>|                    |
    |                          |<-- Claim / Open ---------|                    |
    |-- CPace A -------------->|-- deliver or queue ----->|                    |
    |<-- CPace B --------------|<-------------------------|                    |
    |-- Finished A ----------->|------------------------->|                    |
    |<-- Finished B -----------|<-------------------------|                    |
    |-- sealed intent -------->|------------------------->|-- display -------->|
    |                          |                          |<- approve/decline -|
    |<-- sealed decision ------|<-------------------------|                    |
    |-- sealed payload ------->|------------------------->|-- verify -> grant  |
    |-- ACK / close ---------->|<-- ACK / close ----------|                    |
```

Both Finished values verify before the intent appears. Only approval permits an intent-bound payload to reach the application verifier.

The relay sees addresses, timing, mailbox identifiers, counts, sizes, and expiry.
It never receives the invitation secret or application plaintext, but it can always deny service.

Dependencies point from effectful adapters toward deterministic protocol cores.
See the [governing specification](specs/SPEC-001-reusable-blind-pairing.md) for requirements, contracts, decisions, and the purity boundary.

## API Reference

The [API and integration reference](docs/API.md) maps every public module and explains each trust boundary.
Start with `wire` for recognition, `endpoint::EndpointReducer` for ceremony state, and `profile` for application policy.

Never deserialize untrusted CBOR directly into application structs.
Use the matching `wire::decode_*` recogniser before any semantic action.

Build local Rust API documentation with:

```sh
cargo doc --locked --no-deps --all-features --open
```

## Development

Run the required local checks from the repository root:

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo doc --locked --no-deps --all-features
cargo deny --all-features check
cargo deny --manifest-path fuzz/Cargo.toml --all-features check
tools/run-mutations.sh
tools/run-fuzz-budgets.sh
```

The fuzz gate requires an installed nightly toolchain and `cargo-fuzz`.
The curated mutation gate creates seven insecure variants and verifies that every targeted test rejects its variant.

Use the broad mutation sweep for exploratory gap discovery:

```sh
cargo install cargo-mutants --locked
tools/run-mutant-sweep.sh --jobs 6
```

This sweep does not run in CI and does not replace the curated gate.
It writes ignored results under `mutants.out/`; the [dated evidence record](evidence/mutation-sweep-2026-08-16.md) explains triage and reproduction.

## License

Apache-2.0.

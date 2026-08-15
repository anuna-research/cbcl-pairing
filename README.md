# cbcl-pairing

Reusable blind pairing endpoints and a reference relay for SPEC-072.

This repository is under implementation. It is not approved for production
cryptographic use or production invitation allocation.

## Quick Start

Run the current conformance baseline:

```sh
cargo test --all-targets
```

The suite intentionally contains a behavioural Red Gate until each protocol
component satisfies its assigned conformance tests.

## Usage

No stable API exists yet. Consumers must not enable production pairing.

## Architecture

The library owns deterministic invitation, mailbox, CPace, channel, CBCL, and
profile logic. The relay binary composes only application-unaware mailbox code.

cbcl-rs remains a generic CBCL dependency. It contains no pairing protocol.

## API Reference

Run `cargo doc --no-deps --open` after the public API lands.

## Development

Use Rust 1.85 or newer. Run `cargo fmt --check`, `cargo clippy`, and
`cargo test --all-targets` before review.


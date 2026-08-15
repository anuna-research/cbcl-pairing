# cbcl-pairing

`cbcl-pairing` is the reusable SPEC-072 pairing core: two peers that share a
one-time secret establish an authenticated channel, exchange an explicit
human-readable intent, and release an application grant only after approval.
An optional blind relay gives them asynchronous rendezvous without becoming a
cryptographic endpoint.

The implementation is experimental. Its conformance implementation is
authorised, but production use and production invitation allocation are not.
The human cryptography, adversarial, and independent-endpoint review gates are
still open.

## User experience

1. In one application, the inviter chooses an action such as **Pair agent** or
   **Transfer credential**.
2. The app shows a one-time carrier: normally a QR/deep link or two generated
   words plus relay information.
3. The second user scans, opens, or enters it. Both peers may connect at
   different times during the invitation's bounded lifetime.
4. The peers establish and explicitly confirm the encrypted channel. The relay
   only queues opaque frames.
5. The receiving app shows the fully recognised intent, including the exact
   authority being requested. The user chooses **Approve** or **Decline**.
6. Approval permits one intent-bound payload to reach the application's own
   verifier. Decline, failure, or completion burns the invitation and closes the
   mailbox.

There is no relay login and no server-side pairing endpoint. A relay operator
can observe addresses, timing, mailbox identifiers, counts, sizes, and expiry;
it cannot see the one-time secret, plaintext intent, approval, credential, or
grant. It can always deny service.

## Why it is reusable

The shared layers do not know whether an application is pairing an agent,
transferring a credential, or doing something new:

```text
carrier -> blind mailbox -> CPace + Finished -> projected CBCL session
                                                    |
                                                    v
                                          application profile
                                      intent -> consent -> grant
```

An application supplies an endpoint-local `ApplicationProfile` and an
authoritative `GrantVerifier`. Adding a profile does not change the relay,
mailbox grammar, limiter, or reaper. `cbcl-rs` remains the generic CBCL parser
and R4/R5/R6 engine; it contains no pairing protocol.

The blind mailbox is optional. Peers that already have a direct, bidirectional
transport can carry the same canonical channel frames themselves.

## Repository contents

- `wire`, `context`, `cpace`, and `channel`: canonical recognition, the pinned
  CPace revision-21 exchange, Finished confirmation, and directional AEAD.
- `cbcl_protocol` and `endpoint`: the role-free bootstrap, role projection, and
  security-effect reducer. CBCL owns choreography; the reducer owns only
  invitation consumption, cryptographic gates, consent uniqueness, and erasure.
- `profile`: agent, credential, and synthetic conformance profiles plus the
  extension boundary for other applications.
- `mailbox`, `limiter`, `observability`, and `relay`: application-unaware,
  bounded relay primitives and a reference TCP process.
- `dialects`, `schemas`, and `vectors`: pinned interoperable protocol assets.
- `evidence`: dated red/green conformance records. These are not substitutes
  for the outstanding independent reviews.

## Build and verify

Rust 1.85 or newer is required.

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo doc --no-deps --all-features
tools/run-mutations.sh
tools/run-fuzz-budgets.sh
```

The library is not published on crates.io. During development, use a path or
exact Git revision dependency and preserve the pinned `cbcl-rs` revision.

```toml
[dependencies]
cbcl-pairing = { path = "../cbcl-pairing" }
```

Do not enable a production pairing flow merely because the crate compiles.
The mutation command makes seven deliberately insecure copies and succeeds only
when every targeted test kills its mutant. The fuzz command uses the installed
nightly toolchain and `cargo-fuzz`; it does not retain corpora in Git.

## Documentation

- [API and integration boundary](docs/API.md)
- [Application tutorial](docs/TUTORIAL.md)
- [Relay operator guide](docs/OPERATOR.md)
- [Security model and production gates](docs/SECURITY.md)
- [SPEC-072](https://git.anuna.io/anuna-research/cbcl-bus/src/branch/main/specs/SPEC-072-unified-pairing-mailbox.md)

The executable endpoint composition in `tests/endpoint.rs` and the two-process
relay exercise in `tests/relay_process.rs` are the current end-to-end reference
fixtures.

## Reference relay

The `relay` feature builds `cbcl-pairing-relay`. It is a private, four-byte
big-endian length-delimited TCP listener intended to sit behind TLS/WSS
termination. Allocation is closed by default and the only enabling flag is
explicitly named for conformance use.

```sh
cargo run --features relay --bin cbcl-pairing-relay -- \
  --listen 127.0.0.1:7443 \
  --operator-key-file ./operator.key \
  --check-config
```

See the operator guide before running it. This reference process is not a
production deployment recipe.

## License

Apache-2.0 OR MIT.

# cbcl-pairing

`cbcl-pairing` is the reusable blind-pairing core described by the local draft
SPEC-001 and derived from `cbcl-bus` SPEC-072. Two peers use a one-time secret
to establish an authenticated channel and exchange a human-readable intent.
The application releases a grant only after approval.
An optional blind relay gives them asynchronous rendezvous without becoming a
cryptographic endpoint.

The implementation is experimental. Its conformance implementation is
authorised, but production use and production invitation allocation are not.
The human cryptography, fresh-context adversarial, and named integration/profile
review gates are still open. The local cross-language endpoint vector gate has
passed.

## User experience

1. In one application, the inviter chooses an action such as **Pair agent** or
   **Transfer credential**.
2. The app shows a one-time carrier: normally a QR/deep link or two generated
   words plus relay information.
3. The second user scans, opens, or enters it. Both peers can connect at
   different times during the invitation's bounded lifetime.
4. The peers establish the encrypted channel and verify both Finished values.
   The relay only queues opaque frames.
5. The receiving app shows the fully recognised intent, including the exact
   authority being requested. The user chooses **Approve** or **Decline**.
6. Approval permits one intent-bound payload to reach the application's own
   verifier. Decline, failure, or completion burns the invitation and closes the
   mailbox.

There is no relay login and no server-side pairing endpoint. A relay operator
can observe addresses, timing, mailbox identifiers, counts, sizes, and expiry;
it cannot see the one-time secret, plaintext intent, approval, credential, or
grant. It can always deny service.

## Pairing flows

### Agent carrier

The agent carrier turns uniform generated entropy into two exact English
BIP-39 words. Users never choose the words.

```text
OS CSPRNG: 3 octets
          |
          v
 discard 2 surplus low bits
          |
          v
 22 uniform bits = 11-bit index A || 11-bit index B
          |                              |
          v                              v
    BIP-39 word A                  BIP-39 word B
          \______________________________/
                         |
                         v
 relay origin + numeric nameplate + two words
```

The invitation secret stores both indices as two big-endian `u16` values.
This four-octet encoding carries 22 bits because each index is in `0..2047`.

### Credential carrier

The credential carrier has no human-entered secret.

```text
OS CSPRNG: 16 octets ----------------> 128-bit invitation secret
                                                |
relay origin + direct mailbox ID ---------------+
                                                |
                                                v
                                  QR / deep link / NFC / OS handover
```

Both carriers select the same CPace, channel, CBCL, consent, and mailbox
protocol. Only the carrier and application profile differ.

### End-to-end ceremony

The relay queues a frame when the receiving peer is offline. Every frame shown
below remains opaque to the relay.

```text
Allocator                 Blind relay                 Claimant              Person
    |                           |                          |                    |
    |-- Allocate ------------->|                          |                    |
    |<-- mailbox + membership -|                          |                    |
    |==== invitation through an out-of-band carrier ====>|                    |
    |                           |<-- Claim / Open ---------|                    |
    |-- CPace A -------------->|-- deliver or queue ----->|                    |
    |<-- CPace B --------------|<-------------------------|                    |
    |-- Finished A ----------->|------------------------->|                    |
    |<-- Finished B -----------|<-------------------------|                    |
    |-- sealed intent -------->|------------------------->|-- display -------->|
    |                           |                          |<-- approve/decline -|
    |<-- sealed decision ------|<-------------------------|                    |
    |-- sealed payload ------->|------------------------->|-- verify -> grant  |
    |-- ACK / close ---------->|<-- ACK / close ----------|                    |
```

Both Finished values must verify before the intent appears. A payload exists
only on the approval branch and remains subject to the application's verifier.

Any malformed input, protocol violation, conflicting decision, cancellation,
crowding, or expiry enters one terminal recovery flow:

```text
terminal event -> reject pending effects -> erase keys -> close mailbox
               -> mark invitation spent -> create a fresh invitation to retry
```

## Architecture

### System trust boundary

The applications and endpoints hold semantic and cryptographic state. The
relay holds only bounded mailbox state and local abuse-control state.

```text
            invitation: relay origin + locator + one-time secret
       +-------------------------------------------------------------------->
       |
+------+--+ typed +----------+ opaque +-------------+ opaque +----------+ typed +---------+
| App A   |<----->| Peer A   |<=====>| Blind relay |<=====>| Peer B   |<----->| App B   |
| profile |       | CBCL     | frames | mailbox     | frames | CBCL     |       | profile |
| verifier|       | CPace/AEAD|        | limiter     |        | CPace/AEAD|       | verifier|
+---------+       +----------+        +------^------+        +----------+       +---------+
                                               |
                              local limit decision
                                               |
                        HMAC(operator key, peer address)
```

The relay sees network addresses, timing, sizes, mailbox identifiers, and
expiry. It never receives the invitation secret or decrypted application data.

### Crate and effect boundaries

Dependencies point from effectful adapters toward deterministic protocol
cores. The peer core never imports network, storage, UI, or grant modules.

```text
       application adapter                         relay shell
  UI / CSPRNG / persistence                 WebSocket or private TCP
              |                             clock / CSPRNG / logging
              v                                      |
     +------------------+                             v
     | EndpointReducer  |                   +------------------+
     | authorised effects|                  | RelayService     |
     +---------+--------+                   +----+--------+----+
               |                                 |        |
               v                                 v        v
     +------------------+                  +-----------+  +-------------+
     | CBCL protocol    |                  | mailbox + |  | MailboxStore|
     | CPace + channel  |                  | limiter   |  | adapter     |
     | profile recogniser|                 | pure core |  | effect      |
     +------------------+                  +-----------+  +-------------+
```

CBCL endpoint projections own legal message order and role direction. The
endpoint reducer owns cryptographic gates, one-time consent, effects, and
secret erasure.

## Why the operator has a key

The operator key has one narrow purpose: privacy-preserving rate-limit
dimensions.

```text
canonical peer address
          |
          v
HMAC-SHA256(operator key, address)
          |
          v
opaque PeerKey + operation -> sliding-window bucket -> allow or cooldown
```

An ordinary hash is insufficient because the IP-address space is enumerable.
Anyone holding an unkeyed digest can test likely addresses offline. A private
HMAC key prevents that lookup and gives each operator unrelated peer
pseudonyms.

The key never authenticates peers, derives channel keys, encrypts mailboxes, or
opens invitations. Compromise of this key does not decrypt recorded frames.
Each operator uses a different key, so operators cannot correlate `PeerKey`
values.

The current limiter is memory-only. Therefore, the file-backed key does not
preserve cooldown history across a restart. It mainly establishes operator
separation and an explicit rotation boundary. A startup-generated key is
sufficient for one isolated process; adopting that simpler operator experience
requires an approved specification revision.

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
- `mailbox`, `storage`, `limiter`, `observability`, and `relay`:
  application-unaware, bounded relay primitives plus reference TCP and
  WebSocket processes.
- `dialects`, `schemas`, and `vectors`: pinned interoperable protocol assets.
- `examples/web_demo.rs` and `examples/web-demo`: a loopback browser demo that
  runs the real agent-profile ceremony in one Rust process.
- `evidence`: dated red/green conformance records. These are not substitutes
  for the outstanding independent reviews.

## Browser demo

Run the loopback-only web example, then open `http://127.0.0.1:8088`:

```sh
cargo run --features relay --example web-demo
```

The page creates a fresh agent invitation with OS randomness. The claimant must
enter its natural-decimal nameplate and both exact words before it runs the real
CPace exchange, both Finished checks, authenticated CBCL role cast, intent
recognition, approval or decline, and application grant verification. Invalid
input or an unresolved nameplate can be corrected without touching the
invitation; one valid-but-wrong word pair consumes it without revealing the
intent.

Both endpoints and relay instrumentation live in the same demo process. The
relay panel reports only opaque frame sizes and explains its actual visibility;
it does not start an independent relay deployment, TLS, or production flow.

## Build and verify

Rust 1.85 or newer is required.

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo doc --no-deps --all-features
cargo deny --all-features check
cargo deny --manifest-path fuzz/Cargo.toml --all-features check
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

- [Repository-local SPEC-001](specs/SPEC-001-reusable-blind-pairing.md)
- [API and integration boundary](docs/API.md)
- [Application tutorial](docs/TUTORIAL.md)
- [Relay operator guide](docs/OPERATOR.md)
- [Security model and production gates](docs/SECURITY.md)
- [Design provenance: cbcl-bus SPEC-072](https://git.anuna.io/anuna-research/cbcl-bus/src/branch/main/specs/SPEC-072-unified-pairing-mailbox.md)

The executable endpoint composition in `tests/endpoint.rs` and the two-process
relay exercise in `tests/relay_process.rs` are the current end-to-end reference
fixtures.

## Reference relays

The `relay` feature builds two shells around the same blind `RelayService`.
`cbcl-pairing-relay-ws` is the standard RFC 6455 WebSocket boundary for
applications. `cbcl-pairing-relay` is a private four-byte big-endian
length-delimited TCP boundary for controlled integrations. Both carry one exact
canonical-CBOR protocol message per binary unit, require TLS/WSS termination in
front of the listener, and keep allocation closed by default.

```sh
cargo run --features relay --bin cbcl-pairing-relay-ws -- \
  --listen 127.0.0.1:7443 \
  --operator-key-file ./operator.key \
  --store-dir ./mailboxes \
  --check-config
```

See the operator guide before running it. This reference process is not a
production deployment recipe.

## License

Apache-2.0 OR MIT.

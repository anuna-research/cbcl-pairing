# Relay operator guide

The reference relay is an application-unaware rendezvous and bounded opaque
queue. It is not a CPace endpoint, identity provider, authorisation service, or
credential store.

This guide supports conformance and review deployments only. Production
invitation allocation is not authorised by SPEC-072 yet.

## What the process provides

- two memberships per mailbox;
- ordered opaque frames with acknowledgements and reconnect/open;
- immediate body deletion after acknowledgement or terminal closure;
- a 60–600 second mailbox lifetime and deletion at original expiry;
- per-operation, operator-keyed peer limiting with a 300-second cooldown;
- hard mailbox, queued-byte, and limiter-entry caps;
- closed log and metric dimensions.

It is an in-memory reference service. Restart loses every mailbox, so it is not
a durable production topology.

## Network boundary

`cbcl-pairing-relay` listens on plain TCP using:

```text
uint32 big-endian length || one deterministic-CBOR message
```

Bind it to a private/loopback address and terminate authenticated TLS or WSS in
front of it. Preserve the canonical peer address for limiter input; the current
reference binary uses the direct TCP peer IP, so an untrusted proxy would make
all clients share or spoof limiter identity. Do not expose the listener directly
to the public Internet.

The maximum accepted length-delimited message is 70,000 octets. Every
connection must send `ClientMessage::Bind` before any other operation.

## Operator key

The operator key is 32 random octets used only to HMAC peer-address limiter
dimensions. It is not a mailbox key and does not decrypt anything. Each operator
must generate its own key and restrict the file to its owner.

One local test setup is:

```sh
openssl rand -out ./operator.key 32
chmod 600 ./operator.key
```

The process also accepts exactly 64 lowercase hexadecimal digits with an
optional final newline. On Unix it refuses a key file accessible by group or
others. Rotate the key only with an explicit limiter-reset plan: rotation makes
all existing pseudonymous peer dimensions unreachable.

## Validate configuration

Build the gated binary and check its arguments/key without listening:

```sh
cargo build --features relay --bin cbcl-pairing-relay
target/debug/cbcl-pairing-relay \
  --listen 127.0.0.1:7443 \
  --operator-key-file ./operator.key \
  --check-config
```

Allocation remains disabled in the resulting service. The printed
`allocation=disabled-by-default` value is intentionally not overridden by a
configuration file or environment variable.

## Run a conformance instance

Only an isolated conformance environment may use:

```sh
target/debug/cbcl-pairing-relay \
  --listen 127.0.0.1:7443 \
  --operator-key-file ./operator.key \
  --enable-conformance-allocation
```

The process prints its resolved listen address once. The enabling flag is not a
production enable switch; it exists to exercise the protocol while required
reviews are open.

The reference defaults are 240 attempts per operation per 60 seconds, a 300
second cooldown, 100,000 limiter entries, 10,000 open mailboxes, and 512 MiB of
queued opaque bytes. Operators cannot currently override these compile-time
reference values. A production configuration surface must itself be reviewed.

## Logs and metrics

The reference stderr event has only:

```text
relay_event operation=<closed operation> outcome=<closed outcome>
```

Do not add dynamic log labels for peer addresses or peer keys, mailbox IDs,
nameplates, membership tokens, frame bodies, application IDs, identities,
intent text, or transcript digests. Safe metrics are operation/outcome counters
and aggregate gauges for open mailboxes, queued bytes, and limiter entries.

The in-process service exposes `RelayService::metrics`; the reference TCP shell
does not yet expose a metrics endpoint. Scraping/export is deployment work and
must preserve the closed dimensions.

## Failure and recovery

- Disconnect preserves a mailbox until reconnect, close, crowding, or expiry.
- A third distinct claimant crowds the mailbox and terminally deletes bodies.
- Sequence gaps or conflicting retries close the mailbox.
- Acknowledgement deletes the corresponding queued body immediately.
- Restart of this reference process loses all in-memory mailboxes. Clients must
  recover with fresh invitations; never reuse a carrier.
- A relay can deny, delay, replay, reorder, omit, or fork delivery. Endpoint
  authentication detects integrity-affecting manipulation but cannot restore
  availability.

## Independent operators

There is no distinguished global relay. An invitation names one canonical
relay origin and clients may use any operator that implements the same wire.
Profiles and client code do not change between operators. Operator keys,
limiter dimensions, logs, capacity, and observed network metadata remain local
to each deployment.

`tests/relay_process.rs` starts two isolated processes with distinct operator
keys and exercises both profile labels over the same wire. This is local
implementer evidence; TEST-017 still requires an integration reviewer and full
profile-result evidence before its gate can close.

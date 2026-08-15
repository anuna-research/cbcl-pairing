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

The process supports an explicitly ephemeral in-memory adapter and an atomic
directory-backed adapter. Neither makes the unreviewed protocol production
ready.

## Network boundary

`cbcl-pairing-relay-ws` accepts an RFC 6455 WebSocket and carries exactly one
deterministic-CBOR message in each binary WebSocket message. Text messages are
rejected. This is the reference application-facing shell.

`cbcl-pairing-relay` is the lower-level private TCP shell using:

```text
uint32 big-endian length || one deterministic-CBOR message
```

Bind either shell to a private/loopback address and terminate authenticated TLS
or WSS in front of it. The reference processes do not implement TLS. Preserve
the canonical peer address for limiter input; both binaries use the direct TCP
peer IP, so an untrusted proxy would make all clients share or spoof limiter
identity. Do not expose either listener directly to the public Internet.

The maximum accepted protocol message is 70,000 octets in either shell. Every
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

Build the gated WebSocket binary and check its arguments/key without listening:

```sh
cargo build --features relay --bin cbcl-pairing-relay-ws
target/debug/cbcl-pairing-relay-ws \
  --listen 127.0.0.1:7443 \
  --operator-key-file ./operator.key \
  --store-dir ./mailboxes \
  --check-config
```

Allocation remains disabled in the resulting service. The printed
`allocation=disabled-by-default` value is intentionally not overridden by a
configuration file or environment variable.

`--store-dir` selects canonical, directory-backed mailbox records with private
file permissions and atomic replacement. Records contain only membership
hashes, expiry and sequence metadata, and opaque queued bodies. Omitting the
option selects the deliberately ephemeral memory adapter.

## Run a conformance instance

Only an isolated conformance environment may use:

```sh
target/debug/cbcl-pairing-relay-ws \
  --listen 127.0.0.1:7443 \
  --operator-key-file ./operator.key \
  --store-dir ./mailboxes \
  --enable-conformance-allocation
```

The process prints its resolved listen address once. The enabling flag is not a
production enable switch; it exists to exercise the protocol while required
reviews are open.

For rollback, stop the listener and invoke the same durable configuration with
`--emergency-close`. This disables allocation, deletes every queued body, and
retains only body-free tombstones through each original expiry.

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
- Restart with the memory adapter loses every mailbox. Restart with the
  directory adapter reconstructs mailboxes, queued bodies, acknowledgements,
  and original expiries from canonical records. Never reuse an expired or
  closed carrier in either mode.
- A relay can deny, delay, replay, reorder, omit, or fork delivery. Endpoint
  authentication detects integrity-affecting manipulation but cannot restore
  availability.

## Independent operators

There is no distinguished global relay. An invitation names one canonical
relay origin and clients may use any operator that implements the same wire.
Profiles and client code do not change between operators. Operator keys,
limiter dimensions, logs, capacity, and observed network metadata remain local
to each deployment.

`tests/relay_process.rs` starts two isolated TCP processes with distinct operator
keys and carries complete agent and credential ceremonies over each: CPace,
Finished, projected intent, approval, payload, grant, acknowledgement, and
close. It compares the resulting display/grant state and verifies that logs
remain application-blind. This is local implementer evidence; the production
gate still requires the named integration-review disposition.

`tests/websocket_process.rs` starts the standard WebSocket shell, connects two
real clients, routes an opaque frame asynchronously, rejects text frames, and
checks that process logs contain neither mailbox IDs nor bodies.

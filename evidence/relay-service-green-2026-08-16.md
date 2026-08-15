# Relay service Green Gate — 2026-08-16

Focused commands:

```text
cargo test --test relay_service --all-features
cargo test --test relay_process --features relay
cargo test --test websocket_process --all-features
cargo test --test storage --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

Result: 3 service tests and the two-process TEST-017 local deployment test
passed; strict Clippy passed.

Implemented boundary:

- one bounded `RelayService` composes the existing pure mailbox transition,
  operator-keyed limiter, and closed observability dimensions;
- every command is limiter-gated, `bind` is mandatory, membership tokens are
  retained only as SHA-256 hashes, queued bodies remain opaque, and relay state
  has no application identifier or profile registry;
- direct and nameplate allocation, claim, open/resume, contiguous put, exact
  delivery, acknowledgement deletion, close, crowding, capacity refusal, and
  original-expiry reaping are covered;
- live routing targets only the other membership, while disconnected peers
  receive exact queued bytes after authenticated reopen;
- the TCP process accepts deterministic-CBOR messages under a four-octet length
  prefix, sources identifiers and tokens from the OS CSPRNG, reads its operator
  key from a group/other-inaccessible file, and logs only closed
  operation/outcome labels;
- production allocation is disabled by default and can only be enabled through
  the explicitly named local conformance flag; and
- two isolated relay processes with different operator keys route agent-profile
  and credential-profile opaque bytes with identical protocol results and no
  body/application leakage in logs.

The same blind service now has two reference shells: the existing private
length-delimited TCP listener and an RFC 6455 binary-WebSocket listener. A real
two-client process test proves asynchronous WebSocket routing, exact canonical
CBOR messages, text rejection, and application-blind logs. Both require TLS/WSS
termination by the deployment.

`MailboxStore` now has memory and canonical directory-backed adapters. The file
adapter writes private records through fsync plus atomic rename, reconstructs
queued and acknowledged state after restart, removes interrupted body-bearing
temporary records, retains no raw membership token, and reaps all files at the
original expiry. The runtime allocation kill switch preserves existing
mailboxes; emergency close removes bodies and retains only bounded tombstones.

These are local conformance deployables. Production remains prohibited by the
retained Tier-1 gates.

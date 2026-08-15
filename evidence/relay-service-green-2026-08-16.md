# Relay service Green Gate — 2026-08-16

Focused commands:

```text
cargo test --test relay_service --all-features
cargo test --test relay_process --features relay
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

The TCP listener is an internal reference transport. A deployment terminates
TLS/WSS in front of it; production remains prohibited by the retained Tier-1
gates.

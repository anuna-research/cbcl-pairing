# Red-team report: `cbcl-pairing`

Date: 2026-09-15  
Reviewed commit: `72cd00a`  
Scope: Rust library, TCP and WebSocket relay shells, mailbox persistence, wire recognition, credential/v2 bootstrap and handoff, security and operator documentation.

## Executive summary

The review found no demonstrated confidentiality, authentication, or consent-bypass vulnerability. In particular, this pass did not find a way to skip CPace Finished confirmation, reuse an AEAD nonce, release a grant without approval, admit a third mailbox member, or recover secret material from debug output.

The largest remaining exposure is availability. Both relay shells create one operating-system thread per connection without a connection cap. The TCP shell also permits an unauthenticated client to hold that thread and two socket handles indefinitely without sending a byte. Malformed messages bypass the existing per-peer limiter because recognition happens before `RelayService::handle`. These two properties compose into a practical resource-exhaustion path if a relay listener is reachable by an attacker.

The recent extension of v1 mailbox lifetime to 24 hours also changes the abuse economics substantially. The operator guide still promises a ten-minute maximum, and the service has no per-peer quota for live mailboxes. A client allowed to allocate can accumulate mailbox reservations across limiter cooldown periods and retain them for a day.

Production deployment should remain disabled, consistent with `docs/SECURITY.md`, until RT-01 through RT-04 are addressed and independently retested.

| ID | Severity | Finding | Affected boundary |
| --- | --- | --- | --- |
| RT-01 | High | Unbounded thread-per-connection admission permits remote resource exhaustion | TCP and WebSocket relay shells |
| RT-02 | Medium | Malformed messages bypass per-peer limiting and repeatedly invoke full CBOR/CDDL recognition | TCP and WebSocket relay shells |
| RT-03 | Medium | 24-hour v1 reservations enable cumulative capacity exhaustion; operator contract is stale | Relay allocation and operations |
| RT-04 | Medium | Public CBOR recognizers have no outer input-size guard | Library embedding boundary |
| RT-05 | Low | WebSocket handshake accepts every browser `Origin` | WebSocket relay shell |

## Findings

### RT-01 — Unbounded thread-per-connection admission

**Severity:** High for an attacker-reachable listener; Medium when a reviewed upstream proxy enforces strict connection limits and idle deadlines.

**Evidence**

- `src/bin/cbcl-pairing-relay.rs:112-132` accepts every connection, clones its socket, inserts the writer in an unbounded `BTreeMap`, and calls `thread::spawn`.
- `src/bin/cbcl-pairing-relay.rs:221-240` immediately blocks the new thread in `read_message`.
- `src/bin/cbcl-pairing-relay.rs:315-330` uses blocking `read_exact` calls without a read deadline.
- `src/bin/cbcl-pairing-relay-ws.rs:112-123` also spawns one thread for every accepted socket before any application admission or capacity check.
- The WebSocket shell limits the handshake to five seconds, but each completed handshake receives a dedicated thread and an entry in `senders` with no total or per-peer cap (`src/bin/cbcl-pairing-relay-ws.rs:138-150`). Idle WebSockets remain live indefinitely.
- The relay's configured caps cover mailboxes, queued bytes, and limiter entries. They do not cover connections or worker threads (`src/bin/cbcl-pairing-relay.rs:30-34`, `src/relay.rs:146-150`).

**Attack**

An unauthenticated client opens TCP connections and sends no length prefix. Each connection retains a worker thread, a reader socket, a cloned writer socket, and a map entry indefinitely. Against the WebSocket shell, the client completes cheap handshakes and holds the resulting connections. Repeating this until the process or operating system reaches its thread/file-descriptor limit prevents legitimate clients from connecting and may terminate the process.

The limiter does not help because no `ClientMessage` is required to consume these resources.

**Impact**

Remote denial of service, process instability, and exhaustion of file descriptors, virtual memory reserved for thread stacks, or scheduler capacity.

**Recommendation**

Use a bounded worker model or async runtime with explicit global and per-peer connection semaphores. Add handshake, first-message, idle, and write deadlines to both shells. Refuse excess connections before cloning sockets or spawning workers. Expose rejected-connection and active-connection metrics using closed dimensions. Test that stalled partial length prefixes, stalled bodies, idle WebSockets, and non-reading peers release all resources on schedule.

### RT-02 — Malformed messages bypass the limiter

**Severity:** Medium; combines with RT-01 to increase impact.

**Evidence**

- The WebSocket shell calls `decode_client_message` at `src/bin/cbcl-pairing-relay-ws.rs:161`. On failure it sends 400 and continues at lines 163-171. It calls the limited `RelayService::handle` only at line 192.
- The TCP shell has the same ordering at `src/bin/cbcl-pairing-relay.rs:243-277`.
- The limiter check is inside `RelayService::handle` (`src/relay.rs:204-223`), after shell recognition has succeeded.
- Recognition first materializes a generic `ciborium::Value`, canonicalizes it, recursively searches for duplicate keys, and then performs CDDL validation (`src/wire.rs:367-415`).
- The existing adversarial test intentionally exercises a 69,729-byte reverse-ordered map with 11,621 keys (`tests/recognition.rs:275-303`). The bound controls the cost of one attempt, but failed attempts are unlimited.

**Attack**

After opening one or more connections, an attacker repeatedly sends maximum-size malformed or noncanonical CBOR. Every input pays the full recognition cost but never records an attempt in the peer limiter. Multiple connections parallelize that work across the unbounded worker threads from RT-01.

**Impact**

CPU and allocation pressure outside the stated per-operation abuse budget. Valid clients experience latency or loss of service even though attacker dimensions never enter cooldown.

**Recommendation**

Add a cheap pre-recognition budget keyed by the canonical peer and charged for every frame, including malformed, text, incomplete, and oversized inputs. Keep the semantic per-operation limiter after recognition. Apply a small connection-local invalid-message budget and close the connection when it is exhausted. Measure aggregate recognition time and allocations under many concurrent invalid inputs, not only one input.

### RT-03 — 24-hour reservations permit cumulative capacity exhaustion

**Severity:** Medium when allocation is enabled.

**Evidence**

- v1 mailboxes accept 60 through 86,400 seconds (`src/mailbox.rs:8-12`, `src/mailbox.rs:328-344` and `schemas/pairing-v1.cddl`).
- The reference allocation policy allows 240 allocation attempts per 60-second window, followed by a 300-second cooldown (`src/bin/cbcl-pairing-relay.rs:27-33`).
- Capacity is global: 10,000 open mailboxes and 512 MiB of queued bodies. There is no per-peer live-mailbox or retained-byte quota (`src/bin/cbcl-pairing-relay.rs:30-34`, `src/relay.rs:400-405`).
- A successful allocation attaches only that connection and mailbox; the limiter entry does not track or release active reservations (`src/relay.rs:381-450`).
- `docs/OPERATOR.md:12-18` still states that mailbox lifetime is 60-600 seconds, while `docs/OPERATOR.md:105-108` describes the current global caps.

**Attack**

A client requests the 24-hour lifetime on every allowed allocation. Reservations survive successive five-minute cooldowns, so one source can accumulate them rather than having them expire at the former ten-minute ceiling. Distributed sources accelerate the attack. Once the global mailbox cap is reached, all new allocation attempts receive 503 until enough attacker mailboxes expire. Queued bodies can similarly consume the global byte cap.

**Impact**

Sustained denial of new pairings for up to a day. The stale operator guide can cause operators to size capacity, alerts, and incident response around a retention period 144 times shorter than the implementation permits.

**Recommendation**

Before enabling allocation, add per-peer concurrent mailbox and retained-byte quotas, plus a total allocation lease budget that spans rate-limit windows. Consider requiring an authenticated allocator identity at the deployment edge. Alert on expiry-weighted reserved capacity. Update the operator guide and all deployment calculations to the 86,400-second maximum, or restore the shorter maximum until the new abuse model is approved.

### RT-04 — Public recognizers allocate before enforcing an outer size limit

**Severity:** Medium for applications that pass attacker-controlled byte slices directly to the library; the shipped relay shells mitigate this specific path with 70,000-byte transport limits.

**Evidence**

- `wire::decode_*` functions call `recognise_value`; `recognise_value` deserializes the entire supplied slice into `ciborium::Value` without first checking `input.len()` (`src/wire.rs:395-415`).
- Credential/v2's shared `decode_canonical` does the same (`src/credential_v2/mod.rs:118-135`). Several public decoders reach it, including carrier, frame, object, account-selection, and checkpoint decoders.
- Typed field and body limits are enforced after generic CBOR allocation and canonical re-encoding.
- `docs/API.md:48-53` tells embedders to use the decoders at the untrusted CBOR boundary but does not require a byte cap before calling them.

**Attack**

An embedding application receives an attacker-controlled, very large CBOR byte string, array, or map and calls the documented decoder directly. The decoder allocates and traverses the generic value before discovering that it violates the selected schema or typed size limit. Concurrent requests amplify the memory and CPU cost.

**Impact**

Application-level memory or CPU denial of service. The risk applies outside the reference relay, where the crate cannot assume its shells' 70,000-byte check.

**Recommendation**

Give each public decoder an explicit outer maximum and reject larger slices before CBOR deserialization. Where formats have materially different maxima, use format-specific limits. Document these limits as part of the public trust-boundary contract and add tests proving that one-octet-oversize input returns before invoking the CBOR decoder.

### RT-05 — WebSocket handshake accepts every browser Origin

**Severity:** Low under the documented authenticated reverse-proxy deployment; Medium if the shell is exposed to browsers without an origin policy.

**Evidence**

- `src/bin/cbcl-pairing-relay-ws.rs:138-143` uses `accept_with_config`, which performs no application origin allowlist callback.
- No code in the WebSocket shell reads or validates the `Origin` header.
- Allocation and protocol requests use no browser-bound CSRF token. The protocol intentionally authenticates mailbox membership, not the web origin initiating relay traffic.

**Attack**

A hostile website causes a visitor's browser to connect to a reachable relay, including a locally bound conformance instance where browser network policy permits it. The site can consume the visitor's source-IP limiter budget, use the relay as an allocation/queue service, or interfere with local testing. It cannot derive existing mailbox membership tokens from this behavior alone.

**Impact**

Cross-site relay abuse and source-IP budget consumption. No credential or established-session compromise was demonstrated.

**Recommendation**

Validate `Origin` during the HTTP upgrade against an explicit operator allowlist. Reject missing origins when the service is intended only for browsers; use a separately authenticated policy for non-browser clients. Enforce the same rule at the terminating proxy and test hostile, null, missing, alternate-port, and mixed-case origins.

## Positive security observations

- The crate forbids unsafe code and uses typed, redacted, zeroizing wrappers for several secret-bearing values.
- Wire recognition rejects trailing bytes, noncanonical encoding, duplicate keys, unknown fields, and typed range violations.
- Secure-channel tests cover transcript binding, independent directional keys, Finished corruption, replay, gaps, wrong direction, bad tags, nonce construction, and size bounds.
- Credential/v2 tests cover authenticated display provenance, exact phase/sender/predecessor binding, checkpoint authentication, expiry, recovery, manual pairing, and handoff commitment substitution.
- Relay persistence stores membership hashes rather than raw membership tokens and validates canonical records and mailbox invariants on restart.
- Direct pinned versions checked against the current RustSec records during this review did not reveal an applicable known vulnerability: `tungstenite` 0.30.0 is newer than the 0.20.1 fix for RUSTSEC-2023-0065; `aes-gcm` 0.11.0 is outside the affected 0.10.0-0.10.2 range for RUSTSEC-2023-0096; `ed25519-dalek` 2.2.0 is in the fixed major version for RUSTSEC-2022-0093; and transitive `bytes` 1.12.1 is newer than the 1.11.1 fix for RUSTSEC-2026-0007.

## Verification performed

- `cargo clippy --locked --all-targets --all-features -- -D warnings`: passed.
- `cargo test --locked --all-targets --all-features`: all suites reached during the run passed until `tests/relay_process.rs`; that process test failed before receiving its `LISTEN` line because this review environment prohibits local socket binding (`Operation not permitted`). A focused rerun failed at the same environmental boundary. This is not evidence of a product regression, but the process suite was not green in this environment.
- `cargo deny --all-features check`: not run because `cargo-deny` is not installed. The dependency observation above is a targeted RustSec review, not a substitute for the repository's full deny policy.
- Existing mutation and fuzz evidence was inspected but not treated as independent assurance.

## Remediation order

1. Fix RT-01 and RT-02 together, then load-test concurrent idle, partial, malformed, and non-reading clients.
2. Resolve RT-03 before any allocation-enabled deployment and update the operator contract.
3. Add decoder-level caps for RT-04 so every embedding receives safe defaults.
4. Add an explicit WebSocket origin policy for RT-05.
5. Rerun the full test, fuzz, mutation, dependency, and independent interoperability gates in an environment that permits process-level socket tests.

## Review limitations

This was a source-assisted adversarial review, not a formal proof or a cryptographic certification. It did not include Internet-scale load testing, side-channel measurement, production proxy configuration, mobile/browser integration, external relay interoperability, or a new independent implementation of CPace draft 21. Those remain required by the repository's own production gates.

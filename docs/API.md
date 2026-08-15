# API and integration boundary

The crate is split at two trust boundaries: the application shell owns I/O,
randomness, persistence, UI, and grant side effects; the library recognises
bytes and decides which security effects are legal. The relay is a separate,
application-unaware component.

The API is experimental and may change before SPEC-072 reaches its production
gate.

## Application inputs

An application shell supplies:

- CSPRNG output for mailbox IDs, membership tokens, CPace scalars, ceremony
  signing keys, invitation secrets, and intent nonces;
- exact current time and a canonical peer-address representation where the
  relay API asks for them;
- durable storage for `InvitationRecord` before accepting the first online
  guess;
- transport for canonical `ClientMessage`, `ServerMessage`, and `ChannelFrame`
  bytes;
- one mandatory `ApplicationProfile` and, for real profiles, an application-
  authoritative `GrantVerifier`;
- UI that displays only `EndpointEffect::DisplayIntent`, and applies consent by
  calling `EndpointReducer::decide`;
- application mutation only after `EndpointEffect::DeliverGrant`.

The library does not select a relay operator, create a production invitation,
show UI, persist records, or install a grant.

## Module map

| Module | Responsibility | Typical consumer |
| --- | --- | --- |
| `wire` | Deterministic CBOR/ABNF recognition and encoding | clients and relay shells |
| `context` | Exact SPEC-072 CPace `CI`, `sid`, `ADa`, and `ADb` | clients |
| `cpace` | Pinned CPace255 draft-21 computation | clients |
| `channel` | Transcript, Finished, AES-GCM directions and counters | clients |
| `cbcl_protocol` | Signed controls, monitors, cast, endpoint projection | clients |
| `endpoint` | Security gates and authorised effect release | application adapters |
| `profile` | Intent/payload recognition and grant-verifier boundary | application adapters |
| `mailbox` | Pure two-member blind mailbox transition | relay implementations |
| `limiter` | Bounded operator-keyed per-operation limiter | relay implementations |
| `observability` | Closed, privacy-safe metrics and log dimensions | relay implementations |
| `relay` | Reference in-memory service composition | relay shells/tests |

## Canonical byte boundary

Never deserialize untrusted CBOR directly into application structs. Use the
`decode_*` functions in `wire`; they reject malformed, non-deterministic,
duplicate-key, unknown-key, out-of-range, and trailing input. Emit values with
the matching `encode_*` function.

The nested CPace share is a canonical `CpaceMessage`, encoded with
`encode_cpace_message` and then carried as the opaque `message` byte string of a
`ChannelFrame::Cpace`. Its inner side must equal the signed outer side.

For a SPEC-072 ceremony, call `cpace::start_pairing`. It derives every CPace
application input from the invitation and resolved mailbox and checks the
peer's exact associated data in `cpace::finish`. The lower-level `cpace::start`
exists for official vectors and specialised protocol work; ordinary
applications should not invent their own `CI`, `sid`, or associated data.

## Endpoint lifecycle

The CBCL monitors are the choreography authority. `EndpointReducer` is not a
second protocol graph; it retains only security state that projection alone
cannot represent.

| Phase | Application action | Library gate/effect |
| --- | --- | --- |
| Invitation | Persist `InvitationRecord::new(invitation_bytes)` | status is `Unused` |
| First online guess | Atomically call `record.bind(mailbox, peer_frame, public_context)` before processing the frame | exact resume is allowed; another attempt burns the invitation |
| CPace bootstrap | Run `start_pairing`/`finish`, construct the signed bootstrap controls, then `PendingChannel` | no application effect |
| Finished | Feed controls to `admit_bootstrap_control`; call `local_finished_frame` and `receive_frame` | `Unknown` queues only; both valid HMACs open the channel and role-cast session |
| Intent | Allocator calls `send_intent`; claimant calls `receive_frame` | one fully profile-recognised `DisplayIntent` effect |
| Consent | Claimant calls `decide(Approve)` or `decide(Decline)` | decline emits `CloseMailbox` and erases secrets |
| Payload | After approval, allocator calls `send_payload`; claimant calls `receive_frame` | one digest-bound `DeliverGrant` after one verifier call |
| Terminal | Shell obeys `CloseMailbox` | no invitation or key reuse |

All `SendFrame` effects contain already-protected channel frames. Encode them
before giving them to an untrusted transport. An `EndpointEffect` is a request
to the shell; do not infer an effect from a CBCL `Valid`, `Unknown`, or parsing
result yourself.

## Profiles

`ApplicationProfile` has four jobs:

1. accept only the intended invitation application/carrier;
2. fully recognise claims before returning a safe `DisplayIntent`;
3. bind the recognised intent to a fixed digest-sized `ProfileBinding`;
4. recognise an intent-bound payload and delegate final authorisation to the
   application's `GrantVerifier`.

The built-in profiles are:

- `AgentProfile`: `anuna.io/agent/v1`, with a two-word four-octet carrier;
- `CredentialProfile`: `anuna.io/credential/v1`, with a 16–64 octet carrier;
- `SyntheticProfile`: conformance only, never a production policy.

The agent carrier is exactly two big-endian `u16` indices in `0..=2047`, or 22
bits of generated choice. `encode_agent_word_indices` creates those four bytes;
the application maps indices to its pinned 2048-word list for display and input.

`GrantVerifier` is intentionally application-owned. The pairing crate does not
reinterpret an app's authority, revocation, account, credential, or delegation
rules. An “authorised” result cannot skip Finished or explicit approval because
the reducer does not invoke the verifier before those gates.

## Relay embedding

`RelayService::handle` accepts an already-recognised `ClientMessage` plus an
explicit connection ID, canonical peer-address bytes, time, and shell-generated
randomness. It returns `RoutedMessage` values for one or both live connections.
`disconnect` preserves the mailbox for resume, while `sweep` expires mailboxes
and limiter entries.

The service is in-memory. Durable storage is a deployment choice, but a durable
adapter must retain only the state represented by `MailboxSnapshot` and must
honour identical acknowledgement, closure, terminal deletion, and original-
expiry semantics.

## Errors and terminal handling

Recognition errors mean the bytes never crossed the trust boundary. Reducer
errors may also make the ceremony terminal; inspect `terminal_reason`, obey any
already-emitted `CloseMailbox`, and never retry with the same invitation unless
`InvitationRecord::bind` returned `Resumed` for the exact active binding.

`Debug` implementations redact secret-bearing types, but debug redaction is not
a substitute for avoiding secret copies in application logs, crashes, metrics,
or persistence.

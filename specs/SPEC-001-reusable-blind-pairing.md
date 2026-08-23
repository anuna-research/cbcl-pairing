---
id: SPEC-001
title: Reusable blind pairing
status: draft
tier: 1
mode: reference
version: 0.5.2-draft
last-updated: 2026-08-24
owner-repo: cbcl-pairing
implementation-status: credential-v1-local-complete; credential-v2-unimplemented
implementation-baseline: c22f2d0526432c01c56d64be35a8d4f87516ec92
documentation-baseline: b2a9df8166bf92be8e2207f84830e03c9db9f750
derived-from: cbcl-bus SPEC-072 v0.3.4 at 9b966e04d0a8e21ecc0fe9f8de508f953574edc8
source-spec-sha256: 6fa3c9541aeebd039013413e063592a8903fc5a44d26d051f4ca2520bc35369e
review-gate: production-not-approved
authority-form: consolidated-current-protocol-and-consumer-pointer
consumer-design: selfsame SPEC-008 0.5.3-draft
coordinated-safety-design: selfsame SPEC-007 0.3.1-draft
coordinated-hub-design: cbcl-bus SPEC-053 0.17.3-draft
generation-model-family: OpenAI GPT-5
generation-model-version: gpt-5.6-sol
generation-session: 01a029aa-9127-7c42-ad28-81512b91ded6
generation-synthesis-trajectory: "credential/v2 protocol ancestry through 0.4.8 -> direct 0.5.0 reissue -> rejected 0.5.1 and 0.5.2 coordinated reviews -> complete cryptographic and object authority"
---

# SPEC-001 — reusable blind pairing

This specification governs the `cbcl-pairing` repository. It restates the
accepted intent of its source specification against the completed local
implementation and exact local protocol assets.

This draft does not approve production deployment or production invitation
allocation.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are interpreted as described in BCP 14. Their
special meaning applies only when they appear in all capitals.

## Orientation

**Intent.** Two peers use a one-time secret to establish an authenticated
channel through an untrusted asynchronous relay. Applications reuse the channel
without teaching the relay their identities, consent rules, or payloads.

**Metaphor.** The relay is a left-luggage locker. It stores sealed parcels for
two ticket holders but never opens them or decides what their exchange means.

**Structure.**

```text
 invitation: relay origin + locator + one-time secret
       +-------------------------------------------------------------------->
       |
+------+--+      +-------------+      +-------------+      +-------------+      +---------+
| App A   |----->| Endpoint A  |<====>| Blind relay |<====>| Endpoint B  |----->| App B   |
| CON-005 |      | CON-004/010 |opaque| CON-002/003 |opaque| CON-004/010 |      | CON-005 |
+---------+      +-------------+      +-------------+      +-------------+      +---------+

relay:    two memberships, ordered opaque frames, acknowledgement, expiry
peers:    CPace, both Finished values, authenticated roles, sealed session
profiles: recognised intent, explicit decision, authoritative grant verifier
```

**Decisions.** [[SPEC-001-reusable-blind-pairing#ADR-001]] keeps the relay
application-unaware. [[SPEC-001-reusable-blind-pairing#ADR-003]] places both
PAKE endpoints at peers. [[SPEC-001-reusable-blind-pairing#ADR-007]] keeps the
protocol outside `cbcl-rs`. [[SPEC-001-reusable-blind-pairing#ADR-010]] defines
how this candidate local specification becomes the repository's change
authority after review.

**Load-bearing requirements.**

- [[SPEC-001-reusable-blind-pairing#REQ-002]] keeps the relay outside the
  cryptographic principal set.
- [[SPEC-001-reusable-blind-pairing#REQ-005]] makes a third membership
  terminal.
- [[SPEC-001-reusable-blind-pairing#REQ-008]] blocks application traffic until
  both Finished values verify.
- [[SPEC-001-reusable-blind-pairing#REQ-009]] requires recognised intent and
  explicit approval before a grant.
- [[SPEC-001-reusable-blind-pairing#REQ-013]] consumes an invitation before the
  first online guess.
- [[SPEC-001-reusable-blind-pairing#REQ-015]] gates effects on CBCL verdicts.
- [[SPEC-001-reusable-blind-pairing#NFR-009]] bounds recognition work at the
  anonymous trust boundary.
- [[SPEC-001-reusable-blind-pairing#NFR-010]] prevents queued state from
  amplifying unrelated relay operations.

**Controls.**

- Production invitation allocation remains disabled pending the gates in
  [[SPEC-001-reusable-blind-pairing#Production gates]].
- The relay SHALL NOT derive keys, verify Finished values, or interpret bodies
  under [[SPEC-001-reusable-blind-pairing#REQ-002]].
- A third distinct membership SHALL close the mailbox under
  [[SPEC-001-reusable-blind-pairing#REQ-005]].
- Every invitation SHALL bind before its first peer CPace computation under
  [[SPEC-001-reusable-blind-pairing#REQ-013]].
- Both Finished values SHALL verify before any application message under
  [[SPEC-001-reusable-blind-pairing#REQ-008]].
- No grant SHALL precede exact-intent approval under
  [[SPEC-001-reusable-blind-pairing#REQ-009]].
- Application authorization SHALL NOT replace pairing gates under
  [[SPEC-001-reusable-blind-pairing#REQ-014]].
- `Unknown` and `Violation` SHALL produce no unauthorized effect under
  [[SPEC-001-reusable-blind-pairing#REQ-015]].
- Each membership queues at most 16 frames of at most 69,632 octets under
  [[SPEC-001-reusable-blind-pairing#NFR-002]] and
  [[SPEC-001-reusable-blind-pairing#NFR-004]].
- Mailbox lifetime remains 60–600 seconds under
  [[SPEC-001-reusable-blind-pairing#NFR-005]].
- A maximum-size wire message completes recognition within 100 milliseconds
  under [[SPEC-001-reusable-blind-pairing#NFR-009]].
- A backwards wall-clock step SHALL NOT refuse admission under
  [[SPEC-001-reusable-blind-pairing#NFR-011]].
- Limiter diversity SHALL NOT refuse a new peer solely at the entry cap under
  [[SPEC-001-reusable-blind-pairing#NFR-012]].
- Acknowledgement and terminal closure delete bodies immediately under
  [[SPEC-001-reusable-blind-pairing#NFR-003]].
- Recovery after a terminal result always creates a fresh invitation.

**Open.** Human CPace review, fresh-context adversarial review, named
integration dispositions, profile policy, and owner production approval remain
absent. [[SPEC-001-reusable-blind-pairing#Open questions and retained holds]]
records the owners.

## Provenance and authority

The design source is `cbcl-bus` SPEC-072 v0.3.4 at commit
`9b966e04d0a8e21ecc0fe9f8de508f953574edc8`. Its exact Markdown SHA-256 is the
`source-spec-sha256` value in this document's frontmatter.

The source specification supplies intent, requirements, threat analysis, and
production holds. Local code supplies implementation evidence only. No clause
in this document was inferred solely from observed code behaviour.

The implementation and documentation baseline is `cbcl-pairing` commit
`b2a9df8166bf92be8e2207f84830e03c9db9f750`. Version 0.2.0 measures its
review remediation against that parent until the resulting change is merged.

Until this draft passes stakeholder validation, source SPEC-072 remains the
design authority and this document is its candidate repository-local
restatement. After approval, this specification becomes the standing authority
for changes inside this repository. A wire, cryptographic, dialect, profile, or
production-gate change then requires a merged revision here before
implementation changes.

A compatibility-changing revision also records its effect on source SPEC-072
and every consuming project. This rule prevents an external source document
and local code from drifting silently.

Existing source comments and tests use `SPEC-072` identifiers. Their
`REQ-001`–`REQ-015`, `NFR-001`–`NFR-008`, `CON-001`–`CON-010`, and
`TEST-001`–`TEST-022` labels map one-to-one to this document.

### Normative local assets

The following repository files are normative protocol source:

| Asset | Purpose | Exact SHA-256 |
|---|---|---|
| `schemas/pairing-v1.cddl` | Invitation, mailbox, channel, intent, decision, and payload grammar | `c8f7e57a1a944dd999ebeeb20260368d3315ade26748fbab8361de2643240fc9` |
| `schemas/pairing-v1.abnf` | Application identifiers and lowercase hash forms | `a9274224793f49551d402110f6787c1d2be9034d2a3eb149ea9c8c0ff38cb1fa` |
| `dialects/blind-pairing-bootstrap-v1.cbcl` | Role-free CPace and Finished choreography | `5607ca9c015767c433040e58e261828e6c29d427ec66ce1b76e2294cfecfa8c3` |
| `dialects/blind-pairing-session-v1.cbcl` | Authenticated role projection and consent choreography | `f7908e42da5fe1a63e546f4d5e7619bb20f78d06c43273f8a839e82c459c9805` |

The canonical bootstrap dialect hash is
`sha256:534b42e5f15369a9329bcd655027e535277646f3680aa7beb14cc935723e1465`.
The canonical session dialect hash is
`sha256:465e218843248ed867dfa385e498169607daf49c031fca7173891578e60fab3c`.

Local tests and evidence verify the specification. They do not override it.

## User experience

The allocator selects an application action and creates a one-time invitation.
The claimant receives that invitation through a carrier outside the relay.

```text
Allocator                 Blind relay                 Claimant              Person
    |                           |                          |                    |
    |-- allocate ------------->|                          |                    |
    |<-- mailbox + membership -|                          |                    |
    |==== out-of-band invitation ========================>|                    |
    |                           |<-- claim / open ---------|                    |
    |<======= CPace and Finished as opaque frames =======>|                    |
    |-- sealed intent -------->|------------------------->|-- display -------->|
    |                           |                          |<-- approve/decline -|
    |<-- sealed decision ------|<-------------------------|                    |
    |-- sealed payload ------->|------------------------->|-- verify -> grant  |
    |-- acknowledge / close -->|<-- acknowledge / close --|                    |
```

The agent carrier contains a configured relay origin, numeric nameplate, and
two generated English BIP-39 words. The words carry 22 CSPRNG bits and support
manual entry.

The credential carrier contains a relay origin, direct mailbox identifier, and
16 CSPRNG octets. QR, deep link, NFC, or OS handover carries those bytes.

Carrier entropy follows human bandwidth, not application value. A machine
carrier for an agent can define a future high-entropy profile without changing
the relay or core channel.

## Failure modes

### FM-001: Relay becomes a pairing principal

A relay that performs PAKE becomes a pairing principal and password target.

### FM-002: Application-specific relays drift

Application-specific relays drift in limits, retention, and repairs.

### FM-003: Clear protocol metadata reveals intent

Application names or phases reveal user intent to relay operators.

### FM-004: Simultaneous-presence transport loses availability

Non-queued transport fails when peers connect at different times.

### FM-005: Entropy-specific handshakes diverge

Entropy-specific handshakes create divergent security behaviour.

### FM-006: Consent precedes authentication

Approval before peer authentication presents an untrusted claim as authority.

### FM-007: Retries create an online oracle

Retryable low-entropy attempts turn one invitation into an online oracle.

### FM-008: A broad standards label hides the construction

Broad standards claims hide the exact construction and its review state.

### FM-009: Payload authorization replaces pairing gates

Payload authorization is mistaken for channel authentication or consent.

### FM-010: Handwritten choreography drifts

A handwritten endpoint graph diverges from projected CBCL choreography.

### FM-011: Roles bind before ceremony keys

Session roles bind before the corresponding ceremony keys authenticate.

### FM-012: Conflicting decisions both pass

Two conflicting sibling decisions each pass generic causal checks.

### FM-013: Cross-repository specifications drift

A cross-repository source spec and local implementation drift silently.

### FM-014: Bounded storage is mistaken for bounded work

An anonymous request forces work or allocation proportional to unrelated
retained state. A bounded store can still amplify cheap requests into process
wide CPU, memory, or admission failure.

## Requirements

### REQ-001: One protocol supports many deployments

A conforming project SHALL use [[SPEC-001-reusable-blind-pairing#CON-002]] in a
manner that permits independent operators without a distinguished global
service.

Addresses [[SPEC-001-reusable-blind-pairing#FM-003]] and
[[SPEC-001-reusable-blind-pairing#FM-013]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-002]]
- [[SPEC-001-reusable-blind-pairing#TEST-017]]
- [[SPEC-001-reusable-blind-pairing#OBS-001]]

### REQ-002: The relay is not a pairing principal

The relay SHALL NOT derive pairing keys, verify Finished values, retain
plaintext, or interpret opaque bodies as application content.

Copying bounded ciphertext for routing is not semantic interpretation.

Addresses [[SPEC-001-reusable-blind-pairing#FM-001]] and
[[SPEC-001-reusable-blind-pairing#FM-004]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-002]]
- [[SPEC-001-reusable-blind-pairing#CON-004]]
- [[SPEC-001-reusable-blind-pairing#TEST-002]]
- [[SPEC-001-reusable-blind-pairing#OBS-003]]

### REQ-003: Applications do not change relay behaviour

Adding an application SHALL require only an endpoint-side profile. It requires
no relay endpoint, message, phase, parser, store, limiter, reaper, or deployment
change.

Addresses [[SPEC-001-reusable-blind-pairing#FM-002]] and
[[SPEC-001-reusable-blind-pairing#FM-003]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-005]]
- [[SPEC-001-reusable-blind-pairing#TEST-010]]
- [[SPEC-001-reusable-blind-pairing#OBS-001]]

### REQ-004: The mailbox provides bounded asynchronous delivery

The mailbox SHALL queue each opaque frame until peer acknowledgement, terminal
closure, or original expiry, whichever occurs first.

Addresses [[SPEC-001-reusable-blind-pairing#FM-004]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-003]]
- [[SPEC-001-reusable-blind-pairing#TEST-001]]
- [[SPEC-001-reusable-blind-pairing#TEST-013]]
- [[SPEC-001-reusable-blind-pairing#OBS-002]]

### REQ-005: The mailbox admits only two memberships

The mailbox SHALL allocate at most two memberships and become terminal on a
third distinct claim.

Addresses [[SPEC-001-reusable-blind-pairing#FM-007]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-003]]
- [[SPEC-001-reusable-blind-pairing#TEST-003]]
- [[SPEC-001-reusable-blind-pairing#OBS-001]]

### REQ-006: Abuse control is shared

A conforming relay SHALL apply one bounded limiter across all mailbox
operations. Dimensions contain an operation and operator-keyed peer pseudonym.

Addresses [[SPEC-001-reusable-blind-pairing#FM-002]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-008]]
- [[SPEC-001-reusable-blind-pairing#TEST-015]]
- [[SPEC-001-reusable-blind-pairing#OBS-001]]
- [[SPEC-001-reusable-blind-pairing#OBS-002]]

### REQ-007: CPace authenticates invitation-secret possession

Both peers SHALL run the pinned CPace suite for low-entropy and high-entropy
CSPRNG secrets.

Addresses [[SPEC-001-reusable-blind-pairing#FM-005]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-004]]
- [[SPEC-001-reusable-blind-pairing#TEST-007]]
- [[SPEC-001-reusable-blind-pairing#TEST-016]]
- [[SPEC-001-reusable-blind-pairing#OBS-003]]

### REQ-008: Explicit key verification gates application traffic

A client SHALL NOT send or process application messages before both role-bound
Finished values verify.

Addresses [[SPEC-001-reusable-blind-pairing#FM-006]] and
[[SPEC-001-reusable-blind-pairing#FM-011]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-004]]
- [[SPEC-001-reusable-blind-pairing#TEST-008]]
- [[SPEC-001-reusable-blind-pairing#OBS-003]]

### REQ-009: Intent and approval precede every grant

A client SHALL NOT emit a grant before the approving side accepts the exact
encrypted intent identified by its digest.

The agent and credential profiles require explicit person action.

Addresses [[SPEC-001-reusable-blind-pairing#FM-006]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-005]]
- [[SPEC-001-reusable-blind-pairing#TEST-009]]
- [[SPEC-001-reusable-blind-pairing#TEST-012]]
- [[SPEC-001-reusable-blind-pairing#OBS-003]]

### REQ-010: Relay manipulation never produces acceptance

A client SHALL NOT accept a channel or grant after transcript mismatch,
duplicate counter, sequence gap, invalid tag, or unknown intent digest.

Addresses [[SPEC-001-reusable-blind-pairing#FM-004]] and
[[SPEC-001-reusable-blind-pairing#FM-008]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-003]]
- [[SPEC-001-reusable-blind-pairing#CON-004]]
- [[SPEC-001-reusable-blind-pairing#TEST-011]]
- [[SPEC-001-reusable-blind-pairing#OBS-003]]

### REQ-011: Application profiles own application meaning

Each application profile SHALL define its carrier, claims, approval authority,
displayed intent, payload type, and grant verifier.

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-005]]
- [[SPEC-001-reusable-blind-pairing#CON-006]]
- [[SPEC-001-reusable-blind-pairing#CON-007]]
- [[SPEC-001-reusable-blind-pairing#TEST-010]]
- [[SPEC-001-reusable-blind-pairing#OBS-003]]

### REQ-012: Retention exposes no application namespace

The relay SHALL NOT receive application identifiers, identity claims, intent,
approval, grant type, or grant bodies as cleartext protocol metadata.

Addresses [[SPEC-001-reusable-blind-pairing#FM-003]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-001]]
- [[SPEC-001-reusable-blind-pairing#CON-008]]
- [[SPEC-001-reusable-blind-pairing#TEST-014]]
- [[SPEC-001-reusable-blind-pairing#OBS-001]]

### REQ-013: The endpoint consumes an invitation before its first guess

A client SHALL atomically bind an unused invitation before processing its first
peer CPace message.

The binding contains the resolved mailbox, exact peer frame, and public
transcript context. Only an exact resume retains the active binding.

Success, failure, decline, crowding, cancellation, and expiry leave the
invitation consumed.

Addresses [[SPEC-001-reusable-blind-pairing#FM-007]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-004]]
- [[SPEC-001-reusable-blind-pairing#TEST-006]]
- [[SPEC-001-reusable-blind-pairing#TEST-011]]
- [[SPEC-001-reusable-blind-pairing#OBS-003]]

### REQ-014: Payload authorization never substitutes for pairing

A client SHALL NOT treat payload decryption or authorization as channel
authentication, Finished verification, approval, or invitation consumption.

Addresses [[SPEC-001-reusable-blind-pairing#FM-009]].

Trace:
- [[SPEC-001-reusable-blind-pairing#ADR-008]]
- [[SPEC-001-reusable-blind-pairing#CON-005]]
- [[SPEC-001-reusable-blind-pairing#TEST-019]]
- [[SPEC-001-reusable-blind-pairing#OBS-003]]

### REQ-015: Protocol verdicts precede endpoint effects

After invitation consumption, an endpoint SHALL gate each further effect on the
applicable CBCL verdict.

`Valid` admits the next contract. `Unknown` retains only the exact recognised
message and produces no effect. `Violation` closes and erases secret state.

Addresses [[SPEC-001-reusable-blind-pairing#FM-010]],
[[SPEC-001-reusable-blind-pairing#FM-011]], and
[[SPEC-001-reusable-blind-pairing#FM-012]].

Trace:
- [[SPEC-001-reusable-blind-pairing#ADR-009]]
- [[SPEC-001-reusable-blind-pairing#CON-010]]
- [[SPEC-001-reusable-blind-pairing#TEST-020]]
- [[SPEC-001-reusable-blind-pairing#TEST-021]]
- [[SPEC-001-reusable-blind-pairing#OBS-003]]

## Non-functional requirements

### NFR-001: Human-entered secrets have a measured entropy floor

The agent carrier SHALL encode exactly 22 CSPRNG bits as two independently
selected BIP-39 words and reject user-chosen words.

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-006]]
- [[SPEC-001-reusable-blind-pairing#TEST-006]]

### NFR-002: Per-membership frame count is bounded

Each membership SHALL queue at most 16 frames.

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-002]]
- [[SPEC-001-reusable-blind-pairing#CON-003]]
- [[SPEC-001-reusable-blind-pairing#TEST-013]]
- [[SPEC-001-reusable-blind-pairing#OBS-002]]

### NFR-003: Acknowledgement and terminal closure delete bodies

Acknowledged or terminal queued bodies SHALL be deleted in the same committed
transition.

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-003]]
- [[SPEC-001-reusable-blind-pairing#TEST-013]]
- [[SPEC-001-reusable-blind-pairing#OBS-002]]

### NFR-004: Frame body size is bounded

Each mailbox frame SHALL contain at most 69,632 body octets.

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-002]]
- [[SPEC-001-reusable-blind-pairing#TEST-005]]
- [[SPEC-001-reusable-blind-pairing#OBS-002]]

### NFR-005: Mailbox lifetime is bounded

Each mailbox lifetime SHALL be between 60 and 600 seconds. The default is 600
seconds, and allocation returns the immutable absolute expiry.

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-002]]
- [[SPEC-001-reusable-blind-pairing#TEST-013]]
- [[SPEC-001-reusable-blind-pairing#OBS-002]]

### NFR-006: Terminal metadata expires without extension

Membership hashes and tombstones SHALL be deleted by the original expiry.

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-003]]
- [[SPEC-001-reusable-blind-pairing#TEST-013]]
- [[SPEC-001-reusable-blind-pairing#OBS-002]]

### NFR-007: Independent endpoints remain interoperable

Each endpoint SHALL produce every vector's wire output and terminal state from
that vector's fixed inputs.

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-009]]
- [[SPEC-001-reusable-blind-pairing#TEST-018]]
- [[SPEC-001-reusable-blind-pairing#OBS-003]]

### NFR-008: Normative dialects own endpoint choreography

Endpoints SHALL derive legal predecessors and authenticated directions from the
normative dialects without a duplicate choreography graph.

Trace:
- [[SPEC-001-reusable-blind-pairing#ADR-007]]
- [[SPEC-001-reusable-blind-pairing#ADR-009]]
- [[SPEC-001-reusable-blind-pairing#CON-010]]
- [[SPEC-001-reusable-blind-pairing#TEST-020]]

### NFR-009: Wire recognition work is bounded

Recognition SHALL have `O(n log n)` worst-case work for an `n`-octet wire
message. A 69,729-octet adversarial message SHALL finish within 100
milliseconds in the release test profile.

The timing gate warms the recogniser once and measures one single-threaded
decode with `Instant`. Wall time is a conservative bound on CPU consumption.

Addresses [[SPEC-001-reusable-blind-pairing#FM-014]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-002]]
- [[SPEC-001-reusable-blind-pairing#TEST-023]]
- [[SPEC-001-reusable-blind-pairing#OBS-001]]

### NFR-010: Relay work is independent of unrelated queued state

A relay operation SHALL NOT scan or clone bodies outside its addressed
mailbox. A no-expiry sweep SHALL inspect only the earliest expiry index entry.

Addresses [[SPEC-001-reusable-blind-pairing#FM-014]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-003]]
- [[SPEC-001-reusable-blind-pairing#TEST-024]]
- [[SPEC-001-reusable-blind-pairing#OBS-002]]

### NFR-011: Backwards clock steps preserve admission

The limiter SHALL clamp a backwards wall-clock observation to its latest
observed second. The bounded step SHALL NOT produce an unavailable response.

The reference test uses a 30-second backwards step. Cooldown and window time
remain pinned until wall time reaches the previous high-water mark.

Addresses [[SPEC-001-reusable-blind-pairing#FM-014]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-008]]
- [[SPEC-001-reusable-blind-pairing#TEST-025]]
- [[SPEC-001-reusable-blind-pairing#OBS-002]]

### NFR-012: Peer diversity preserves limiter admission

One IPv6 `/64` SHALL consume at most one peer dimension per operation.
Reaching the entry cap SHALL evict the least-recently-used dimension before
admitting a new peer dimension.

Addresses [[SPEC-001-reusable-blind-pairing#FM-014]].

Trace:
- [[SPEC-001-reusable-blind-pairing#CON-008]]
- [[SPEC-001-reusable-blind-pairing#TEST-026]]
- [[SPEC-001-reusable-blind-pairing#OBS-002]]

## Architecture decisions

### ADR-001: The relay is application-unaware

The relay accepts no application identifier and enforces no application phase.
This choice preserves reuse and hides semantic metadata. Endpoints reject
application-invalid order before any approved effect.

### ADR-002: The mailbox adopts Wormhole's operational shape

The protocol keeps allocation, claim, opaque messages, acknowledgement, close,
and expiry. Per-sender sequences replace application-named phases.

### ADR-003: Both key-agreement endpoints are peers

The allocator and claimant run CPace. The relay only transports their frames.
This placement removes password-equivalent material from the relay.

### ADR-004: One CPace construction serves both entropy classes

Version 1 uses `CPACE25519-SHA512-D21` for manual and machine carriers. One
construction avoids an authentication-profile fork.

### ADR-005: Channel and application profiles are separate layers

The shared channel authenticates the invitation and gates consent. Each profile
recognises meaning and delegates final authorization to its application.

### ADR-006: One protocol does not require one operator

Every invitation names a relay origin. Independent operators implement the same
blind wire without a global registry.

### ADR-007: Pairing owns protocol assets outside cbcl-rs

This repository owns schemas, dialects, vectors, CPace composition, and profile
logic. `cbcl-rs` remains a generic CBCL parser and verifier.

### ADR-008: Peer authentication and payload authorization remain separate

Application authorization occurs only after channel authentication and explicit
approval. An ABE or policy envelope inside the payload changes no pairing gate.

### ADR-009: Authentication splits bootstrap from role projection

The role-free dialect admits CPace and Finished controls. Only authenticated
ceremony keys enter the projected allocator and claimant roles.

### ADR-010: This repository carries its governing specification

During review, SPEC-072 remains the design authority and this SPEC-001 is its
candidate local restatement. After this document is approved, SPEC-072 remains
provenance, this SPEC-001 governs changes within `cbcl-pairing`, and
compatibility changes require explicit cross-repository reconciliation.

### ADR-011: Relay work uses indexes and incremental accounting

The standard library supplies ordered sets and maps for every new index.
The relay maintains queued-byte, membership, expiry, and limiter-recency
indexes beside their owning state.

Persistence snapshots remain complete and body-bearing. Internal admission,
gauge, lookup, and sweep paths use non-cloning accessors and indexes.

This placement keeps mailbox transitions and limiter decisions in the pure
core. The effectful relay shell owns only aggregate indexes over stored cores.

Alternative full-state scans preserve one representation but violate
[[SPEC-001-reusable-blind-pairing#NFR-010]]. A new cache dependency adds no
required capability beyond `BTreeMap` and `BTreeSet`.

## Contracts

### CON-001: Invitation and carrier boundary

The exact grammar is `schemas/pairing-v1.cddl` plus
`schemas/pairing-v1.abnf`. Both peers fully recognise deterministic CBOR before
network activity.

An invitation contains version 1, suite `CPACE25519-SHA512-D21`, application
identifier, canonical relay origin, locator, secret, and optional ceremony-key
digests.

The relay origin uses HTTPS or WSS with a lowercase ASCII host. It has no user
information, fragment, or non-root path.

Locator mode 0 carries a 32-octet mailbox identifier. Locator mode 1 carries a
numeric nameplate in `0..999999999`. A nameplate contributes no secret entropy.
The reference shell rejection-samples a uniform value from this exact range.

The invitation never enters the relay as one object. Carrier decoding yields
exact PRS octets without normalization or case folding.

Implements:
- [[SPEC-001-reusable-blind-pairing#REQ-012]]

Verified by:
- [[SPEC-001-reusable-blind-pairing#TEST-005]]
- [[SPEC-001-reusable-blind-pairing#TEST-028]]

### CON-002: Blind mailbox wire protocol

The exact client and server grammar is `schemas/pairing-v1.cddl`. The wire uses
RFC 8949 deterministic CBOR.

Full recognition parses one complete value and rejects trailing octets. It
then rejects non-deterministic encoding before scanning canonical keys in an
ordered set. Schema and typed projection follow without state effects.

Each connection sends `bind` first. Allocation creates a CSPRNG mailbox
identifier and membership token. The relay stores only the token's SHA-256
digest.

The WebSocket shell carries one canonical message per binary WebSocket message.
The private TCP shell carries a four-octet big-endian length followed by one
canonical message. Both shells reject messages above 70,000 octets.

Implements:
- [[SPEC-001-reusable-blind-pairing#REQ-001]]
- [[SPEC-001-reusable-blind-pairing#REQ-002]]
- [[SPEC-001-reusable-blind-pairing#REQ-003]]
- [[SPEC-001-reusable-blind-pairing#NFR-004]]
- [[SPEC-001-reusable-blind-pairing#NFR-005]]

Verified by:
- [[SPEC-001-reusable-blind-pairing#TEST-002]]
- [[SPEC-001-reusable-blind-pairing#TEST-005]]
- [[SPEC-001-reusable-blind-pairing#TEST-017]]

### CON-003: Mailbox state and delivery

```text
absent --allocate--> waiting(A) --first claim--> paired(A,B)
                         |                           |
                         +----- close / expiry -----+
                                                     v
terminal <---------------- third claim ------------ crowded
```

Each membership owns a contiguous sequence from zero. The next sequence stores
and routes the frame. An identical retry is idempotent.

The relay generates each claimant token once. A token-hash collision returns
conflict and never becomes a successful repeated claim.

A sequence gap returns conflict without storage. A different body at an
existing sequence closes the mailbox as conflict.

Acknowledgement deletes the corresponding body. Closing, crowding, conflict,
or expiry deletes every queued body. Metadata remains only until original
expiry.

The included memory and file stores retain only blind `MailboxSnapshot` state.
The file store uses private permissions, canonical records, fsync, and atomic
rename. Restart removes interrupted temporary body records.

The relay maintains queued bytes incrementally. It indexes membership hashes
and absolute expiries without copying queued bodies. Persistence alone uses
the complete snapshot representation.

Implements:
- [[SPEC-001-reusable-blind-pairing#REQ-004]]
- [[SPEC-001-reusable-blind-pairing#REQ-005]]
- [[SPEC-001-reusable-blind-pairing#NFR-002]]
- [[SPEC-001-reusable-blind-pairing#NFR-003]]
- [[SPEC-001-reusable-blind-pairing#NFR-006]]
- [[SPEC-001-reusable-blind-pairing#NFR-010]]

Verified by:
- [[SPEC-001-reusable-blind-pairing#TEST-001]]
- [[SPEC-001-reusable-blind-pairing#TEST-003]]
- [[SPEC-001-reusable-blind-pairing#TEST-004]]
- [[SPEC-001-reusable-blind-pairing#TEST-013]]
- [[SPEC-001-reusable-blind-pairing#TEST-024]]
- [[SPEC-001-reusable-blind-pairing#TEST-029]]

### CON-004: CPace pairing channel

This provisional contract pins `draft-irtf-cfrg-cpace-21`. The allocator is
side A, and the claimant is side B.

| CPace input | Pairing value |
|---|---|
| `PRS` | Exact invitation-secret octets |
| `sid` | Resolved 32-octet mailbox identifier |
| `CI` | Canonical protocol, suite, application, relay, mailbox, and ordered-role context |
| party identifiers | `allocator` and `claimant`, extended by optional expected key digests |
| `ADa`, `ADb` | Canonical sender role and optional expected key digest |

The canonical context shapes are:

```cddl
pairing-ci = [
  "cbcl-pairing-ci/v1", 1, "CPACE25519-SHA512-D21",
  application-id, relay-origin, mailbox-id, ["allocator", "claimant"]
]

pairing-ad = [
  "cbcl-pairing-ad/v1", "allocator" / "claimant",
  bstr .size 32 / null
]

pairing-public-context = [
  "cbcl-pairing-public-context/v1", 1, "CPACE25519-SHA512-D21",
  application-id, relay-origin, mailbox-id,
  bstr .size 32 / null, bstr .size 32 / null
]
```

Each peer owns one ephemeral Ed25519 ceremony key. CPace frames bind their exact
adjacent message through canonical signed CBCL controls.

`TH` is SHA-512 over canonical CBOR containing the public context, allocator
CPace frame, and claimant CPace frame in that order.

```text
PRK      = HKDF-Extract("", ISK)
KC_A     = HKDF-Expand(PRK, "pairing-v1 kc A" || TH, 32)
KC_B     = HKDF-Expand(PRK, "pairing-v1 kc B" || TH, 32)
KEY_A_B  = HKDF-Expand(PRK, "pairing-v1 key A-B" || TH, 32)
KEY_B_A  = HKDF-Expand(PRK, "pairing-v1 key B-A" || TH, 32)
IV_A_B   = HKDF-Expand(PRK, "pairing-v1 iv A-B" || TH, 12)
IV_B_A   = HKDF-Expand(PRK, "pairing-v1 iv B-A" || TH, 12)
EXPORTER = HKDF-Expand(PRK, "pairing-v1 exporter" || TH, 32)

Finished_A = HMAC-SHA-512(KC_A, "pairing-v1 finished A" || TH)
Finished_B = HMAC-SHA-512(KC_B, "pairing-v1 finished B" || TH)
```

Application traffic starts only after both Finished values verify in constant
time. AES-256-GCM protects later envelopes.

Each direction has a contiguous counter from zero. The nonce is the direction
IV XOR the 96-bit big-endian counter. Additional data binds version, direction,
counter, and `TH`.

Duplicate counters, gaps, invalid tags, failed Finished values, or malformed
envelopes close the ceremony and erase keys.

Implements:
- [[SPEC-001-reusable-blind-pairing#REQ-007]]
- [[SPEC-001-reusable-blind-pairing#REQ-008]]
- [[SPEC-001-reusable-blind-pairing#REQ-010]]
- [[SPEC-001-reusable-blind-pairing#REQ-013]]

Verified by:
- [[SPEC-001-reusable-blind-pairing#TEST-006]]
- [[SPEC-001-reusable-blind-pairing#TEST-007]]
- [[SPEC-001-reusable-blind-pairing#TEST-008]]
- [[SPEC-001-reusable-blind-pairing#TEST-011]]
- [[SPEC-001-reusable-blind-pairing#TEST-016]]

### CON-005: Intent, decision, payload, and profile boundary

The exact deterministic CBOR grammar is `schemas/pairing-v1.cddl`. Intent,
decision, and payload values appear only inside authenticated encryption.

The intent contains application, action, both claim bodies, authority summary,
and a 32-octet nonce. Its digest is SHA-256 over exact canonical bytes.

Approval authorizes only the matching intent digest. Decline closes, erases
keys, and produces no payload. A conflicting decision closes with no grant.

Each profile fully recognises both claims before display. It recognises the
payload before calling its application-owned `GrantVerifier`.

An ABE, IBE, broadcast, or attribute-proof envelope can appear inside the
payload. It never advances pairing state or replaces any pairing gate.

Implements:
- [[SPEC-001-reusable-blind-pairing#REQ-009]]
- [[SPEC-001-reusable-blind-pairing#REQ-011]]
- [[SPEC-001-reusable-blind-pairing#REQ-014]]
- [[SPEC-001-reusable-blind-pairing#REQ-015]]

Verified by:
- [[SPEC-001-reusable-blind-pairing#TEST-009]]
- [[SPEC-001-reusable-blind-pairing#TEST-012]]
- [[SPEC-001-reusable-blind-pairing#TEST-019]]
- [[SPEC-001-reusable-blind-pairing#TEST-022]]

### CON-006: Agent profile

```text
application       anuna.io/agent/v1
carrier           configured relay + numeric nameplate + two words
PRS               two big-endian BIP-39 indices
approval          explicit person action
display           channel, claimed principal, agent handle, requested grant
```

The generator consumes three CSPRNG octets and discards two surplus low bits.
It splits the remaining 22 bits into two independent 11-bit indices.

Each index is encoded as an unsigned big-endian `u16` in `0..2047`. Received
words use exact English BIP-39 recognition without normalization.

Implements:
- [[SPEC-001-reusable-blind-pairing#REQ-011]]
- [[SPEC-001-reusable-blind-pairing#NFR-001]]

Verified by:
- [[SPEC-001-reusable-blind-pairing#TEST-006]]
- [[SPEC-001-reusable-blind-pairing#TEST-012]]

### CON-007: Credential profile

```text
application       anuna.io/credential/v1
carrier           QR, deep link, NFC, or OS handover
PRS               16 CSPRNG octets
locator           direct 32-octet mailbox identifier
approval          explicit person action
display           application ID, HTTPS origin, requested scope
```

The machine carrier transports relay origin, locator, and secret. A typed or
spoken credential code is excluded.

The 16-octet secret enters CPace directly. It is not expanded into a claimed
256-bit PSK.

Implements:
- [[SPEC-001-reusable-blind-pairing#REQ-011]]

Verified by:
- [[SPEC-001-reusable-blind-pairing#TEST-007]]
- [[SPEC-001-reusable-blind-pairing#TEST-012]]

### CON-008: Abuse control, storage, and logging

The limiter dimension is `{operation, PeerKey}`. `PeerKey` equals
HMAC-SHA-256 over a family tag and one canonical address prefix. IPv4 uses
`/32`, IPv4-mapped IPv6 uses its IPv4 `/32`, and other IPv6 uses `/64`.

The operator key never authenticates peers, derives channel keys, encrypts
mailboxes, or opens invitations. Each operator uses an independent key.

The reference policy permits 240 attempts per operation in 60 seconds. Exceeding
the budget starts a 300-second cooldown.

The limiter holds at most 100,000 dimensions. At capacity, it evicts the
least-recently-used dimension before inserting a new one. It never refuses a
new peer solely because this cap is full.

The limiter clamps backwards time to its process-local high-water mark. It
records an aggregate reversal count and never extends stored mailbox expiry.

The relay holds at most 10,000 open mailboxes and 512 MiB of queued opaque
bodies.

Logs contain only closed operation and outcome labels. Metrics contain closed
counters and aggregate gauges.

The current limiter is memory-only. A file-backed operator key does not preserve
cooldown history across restart.

Implements:
- [[SPEC-001-reusable-blind-pairing#REQ-006]]
- [[SPEC-001-reusable-blind-pairing#REQ-012]]
- [[SPEC-001-reusable-blind-pairing#NFR-003]]
- [[SPEC-001-reusable-blind-pairing#NFR-011]]
- [[SPEC-001-reusable-blind-pairing#NFR-012]]

Verified by:
- [[SPEC-001-reusable-blind-pairing#TEST-013]]
- [[SPEC-001-reusable-blind-pairing#TEST-014]]
- [[SPEC-001-reusable-blind-pairing#TEST-015]]
- [[SPEC-001-reusable-blind-pairing#TEST-025]]
- [[SPEC-001-reusable-blind-pairing#TEST-026]]

### CON-009: Implementation-neutral endpoint boundary

A conforming endpoint consumes only public schemas, dialects, vectors, fixed
randomness, and explicit time. Language, source layout, and function API remain
local choices.

Each vector fixes role, invitation, inbound frames, randomness, time, expected
bytes, verdicts, effects, and terminal classification.

Secret-bearing state is erased on every terminal path.

Implements:
- [[SPEC-001-reusable-blind-pairing#NFR-007]]
- [[SPEC-001-reusable-blind-pairing#NFR-008]]

Verified by:
- [[SPEC-001-reusable-blind-pairing#TEST-018]]
- [[SPEC-001-reusable-blind-pairing#TEST-020]]

### CON-010: CBCL bootstrap and projected session dialects

The exact dialect files and hashes appear under
[[SPEC-001-reusable-blind-pairing#Normative local assets]].

The bootstrap dialect is role-free. Both CPace controls precede both Finished
controls. Each control binds its adjacent body digest and length.

After both Finished values verify, the allocator sends one effect-free
`with-roles` opener. It maps authenticated ceremony keys to allocator and
claimant roles and pins the canonical session dialect hash.

The session projection permits:

```text
begin -> intent -> approve -> payload
                \-> decline -> terminal
```

The allocator sends intent and payload. The claimant sends approval or decline.
The endpoint ledger makes the first decision atomic because generic CBCL treats
sibling decisions independently.

Controls use canonical RFC 9804 CBCL text and strict Ed25519 signatures. A
control is at most 2,048 octets and depth 8.

The reference implementation pins `cbcl-core` and `cbcl-parser` to `cbcl-rs`
revision `febc6691e6dd2d5f7116b1a4d84c984b64717564`. That dependency supplies
generic CBCL parsing and verification only; it contains no pairing protocol or
cryptography.

Implements:
- [[SPEC-001-reusable-blind-pairing#REQ-008]]
- [[SPEC-001-reusable-blind-pairing#REQ-009]]
- [[SPEC-001-reusable-blind-pairing#REQ-015]]
- [[SPEC-001-reusable-blind-pairing#NFR-008]]

Verified by:
- [[SPEC-001-reusable-blind-pairing#TEST-020]]
- [[SPEC-001-reusable-blind-pairing#TEST-021]]
- [[SPEC-001-reusable-blind-pairing#TEST-022]]

## Purity Boundary Map

### Pure core

- `wire` recognises and encodes deterministic values.
- `mailbox` computes two-member mailbox transitions.
- `limiter` computes bounded abuse-control transitions from explicit time.
- `context`, `cpace`, and `channel` compute peer cryptographic state.
- `cbcl_protocol` installs dialects and returns protocol verdicts.
- `endpoint` maps verified inputs to authorized effects.
- `profile` recognises profile claims and payloads.

### Effectful shell

- Application adapters supply randomness, time, transport, persistence, UI,
  and grant effects.
- Relay binaries supply WebSocket or TCP I/O, peer addresses, clocks,
  randomness, storage transactions, and logs.
- `MailboxStore` adapters perform memory or filesystem persistence.

### Boundary contracts

- Raw bytes cross only through exact grammar recognisers.
- Typed commands enter pure transitions.
- CBCL `Valid`, `Unknown`, and `Violation` verdicts enter the endpoint ledger.
- Only `EndpointEffect` values authorize shell actions.
- Application payloads leave the core only after every pairing gate passes.

### Dependency rule

Dependencies point inward. Pure core modules MUST NOT import network, process,
environment, UI, or application-grant implementations.

### Enforcement

Module visibility, `unsafe_code` denial, strict linting, properties, mutations,
and integration tests enforce the boundary.

## Observability

### OBS-001: Relay operation outcomes

`pairing_mailbox_operations_total{operation,outcome}` uses closed labels. It
contains no peer, locator, mailbox, application, or payload value.

### OBS-002: Relay bounded-state signals

Aggregate gauges expose open mailboxes, queued bytes, and limiter entries.
An aggregate counter exposes backwards limiter-clock observations. These
signals contain no per-peer or per-mailbox label.

### OBS-003: Endpoint pairing outcomes

Endpoint integrations record closed phase and terminal-reason labels. They do
not record invitations, transcript digests, claims, intent text, or payloads.

## Verification plan and implementation evidence

### Core tests

#### TEST-001: Offline peer receives queued frames

Allocate, disconnect one peer, queue a frame, reconnect, and acknowledge it.
Verify exact delivery and immediate deletion.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-004]].
Evidence: `tests/mailbox.rs`, `tests/relay_service.rs`.

#### TEST-002: Relay state contains no pairing semantics

Inspect memory, durable records, logs, and public snapshots. Verify absence of
PRS, application identifiers, claims, intent, decisions, and plaintext.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-002]].
Evidence: `tests/mailbox.rs`, `tests/storage.rs`.

#### TEST-003: Third membership crowds the mailbox

Claim one mailbox with three distinct memberships. Verify terminal crowding,
body deletion, and no third token.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-005]].
Evidence: `tests/mailbox.rs`.

#### TEST-004: Sequence immutability and idempotency

Verify exact retries are inert. Verify gaps and conflicting retries cannot
store or route an unauthorized body.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-004]].
Evidence: `tests/mailbox.rs`.

#### TEST-005: Complete recognition precedes effects

Run every valid and malformed invitation, mailbox message, channel frame, and
application body through the canonical recognisers.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-012]],
[[SPEC-001-reusable-blind-pairing#NFR-004]].
Evidence: `tests/recognition.rs`, `fuzz/fuzz_targets/wire_recognition.rs`.

#### TEST-006: Wrong secret consumes one invitation

Bind before the first peer CPace computation. Verify alternate attempts fail,
exact crash resume remains exact, and wrong-secret Finished fails terminally.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-013]],
[[SPEC-001-reusable-blind-pairing#NFR-001]].
Evidence: `tests/cpace.rs`, `tests/endpoint.rs`, `tests/profiles.rs`.

#### TEST-007: Both entropy classes use one CPace flow

Run the agent and credential PRS forms through identical CPace operations.
Verify no entropy-specific protocol branch.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-007]].
Evidence: `tests/cpace.rs`, `tests/profiles.rs`.

#### TEST-008: Finished gates application traffic

Corrupt either Finished value and attempt application traffic. Verify no
channel activation, role cast, intent, approval, payload, or grant.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-008]].
Evidence: `tests/channel.rs`, `tests/endpoint.rs`.

#### TEST-009: Decline has no grant side effect

Display one valid intent and decline it. Verify close, key erasure, and absence
of payload and grant effects.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-009]].
Evidence: `tests/endpoint.rs`.

#### TEST-010: A new application does not change the relay

Run agent, credential, and synthetic profiles over identical relay assets.
Verify the relay source, grammar, state, and logs remain application-blind.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-003]],
[[SPEC-001-reusable-blind-pairing#REQ-011]].
Evidence: `tests/profiles.rs`, `tests/relay_process.rs`.

#### TEST-011: Relay manipulation cannot produce acceptance

Exercise replay, reordering, omission, fork, sequence gap, bad tag, and
post-activation Finished replay. Verify terminal failure without grant bypass.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-010]],
[[SPEC-001-reusable-blind-pairing#REQ-013]].
Evidence: `tests/channel.rs`, `tests/endpoint.rs`.

#### TEST-012: Approval binds one intent

Approve one intent digest, then present another payload or decision. Verify one
grant for the exact approved digest only.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-009]],
[[SPEC-001-reusable-blind-pairing#REQ-011]].
Evidence: `tests/endpoint.rs`, `tests/profiles.rs`.

#### TEST-013: Expiry and closure bound retention

Verify body deletion on acknowledgement and terminal closure. Advance to
original expiry and verify removal of all mailbox-domain state.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-004]],
[[SPEC-001-reusable-blind-pairing#NFR-002]],
[[SPEC-001-reusable-blind-pairing#NFR-003]],
[[SPEC-001-reusable-blind-pairing#NFR-005]],
[[SPEC-001-reusable-blind-pairing#NFR-006]].
Evidence: `tests/mailbox.rs`, `tests/storage.rs`.

#### TEST-014: Logs and metrics contain no sensitive dimensions

Run success, failure, crowding, expiry, and rate-limit cases. Verify only
closed labels and aggregate gauges appear.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-012]].
Evidence: `tests/limiter_observability.rs`, `tests/relay_process.rs`.

### Depth tests

#### TEST-015: Limiter remains bounded under churn

Drive all operations across rotating addresses. Verify keyed dimensions,
per-operation budgets, cooldown, periodic sweep, and hard entry cap.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-006]].
Evidence: `tests/limiter_observability.rs`.

#### TEST-016: Independent CPace vectors and human review

Verify revision-21 group vectors, context, role binding, key schedule, Finished,
nonce construction, and negative cases.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-007]],
[[SPEC-001-reusable-blind-pairing#REQ-008]].
Local evidence: `tests/cpace.rs`, `tests/context.rs`, `tests/channel.rs`.
External hold: a second group implementation and named human cryptographer.

#### TEST-017: Independent operators interoperate

Run both profiles through two independently operated conforming relays. Verify
identical application results and operator-local metadata.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-001]].
Local evidence: `tests/relay_process.rs`, `tests/websocket_process.rs`.
External hold: named reviewer evidence from independent operations.

#### TEST-018: Independent endpoint implementations agree

Run fixed invitations, contexts, controls, channel values, application events,
and terminal cases through independent endpoints.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-001]],
[[SPEC-001-reusable-blind-pairing#NFR-007]].
Local evidence: `tools/reference_endpoint.py`, `tests/independent_endpoint.rs`.
External hold: named integration-reviewer disposition.

#### TEST-019: Authorization cannot bypass pairing gates

Return authorized before Finished, before approval, and after decline. Verify
no channel, approval, consumption, or grant bypass.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-014]].
Evidence: `tests/endpoint.rs`, mutation `06-authorization-is-approval.patch`.

#### TEST-020: Normative dialects install and project

Install only exact source and canonical hashes. Verify signatures, body
bindings, mutation rejection, role projection, and complementary directions.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-015]],
[[SPEC-001-reusable-blind-pairing#NFR-008]].
Evidence: `tests/dialects.rs`, `tests/cbcl_protocol.rs`.

#### TEST-021: Bootstrap verdicts gate role projection

Feed valid, unknown-predecessor, and violating bootstrap controls. Verify only
the complete authenticated fan-in opens the session cast.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-015]].
Evidence: `tests/cbcl_protocol.rs`, `tests/endpoint.rs`.

### Review-remediation core tests

#### TEST-022: Conflicting decisions release no payload

Present both sibling decisions and reordered decision controls. Verify atomic
first-decision behaviour, terminal conflict, and no grant after decline.

Validates: [[SPEC-001-reusable-blind-pairing#REQ-009]],
[[SPEC-001-reusable-blind-pairing#REQ-015]].
Evidence: `tests/cbcl_protocol.rs`, `tests/endpoint.rs`.

#### TEST-023: Maximum wire recognition has bounded work

Warm the recogniser with one valid message. Decode a 69,729-octet reverse-key
map and require deterministic-encoding rejection.

Under the release profile, require completion within 100 milliseconds. Decode
a canonical duplicate-key input and require duplicate rejection.

Validates: [[SPEC-001-reusable-blind-pairing#NFR-009]].
Evidence: `tests/recognition.rs`.

#### TEST-024: Unrelated queued bodies do not amplify relay work

Load 200 mailboxes containing at least 200 MiB of queued opaque bodies. Track
allocations while processing Ping and a no-expiry sweep.

Require both operations to allocate less than 64 KiB. Require gauges and body
bytes to remain unchanged.

Validates: [[SPEC-001-reusable-blind-pairing#NFR-010]].
Evidence: `tests/relay_work_bounds.rs`.

#### TEST-025: A backwards clock step does not brick admission

Admit one operation at time 1,000. Submit another at time 970 and require a
normal limiter decision with one recorded reversal.

Repeat through `RelayService` and require a protocol response other than 503.

Validates: [[SPEC-001-reusable-blind-pairing#NFR-011]].
Evidence: `tests/limiter_observability.rs`, `tests/relay_service.rs`.

#### TEST-026: Limiter diversity remains bounded without shared refusal

Submit distinct IPv6 addresses from one `/64` and require one peer dimension
per operation. Fill a small limiter, refresh one entry, and add another peer.

Require fixed entry count, least-recently-used eviction, and allowed admission.

Validates: [[SPEC-001-reusable-blind-pairing#NFR-012]].
Evidence: `tests/limiter_observability.rs`.

#### TEST-027: WebSocket oversize input returns the contract error

Send one 70,001-octet binary WebSocket message. Require a canonical
`Error(413)` response before the relay closes that connection.

Validates: [[SPEC-001-reusable-blind-pairing#CON-002]].
Evidence: `tests/websocket_process.rs`.

#### TEST-028: Nameplate sampling has no modulo bias

Supply `4,000,000,000` followed by `3,999,999,999` to the sampler. Require
rejection of the first value and output `999,999,999` from the second.

Validates: [[SPEC-001-reusable-blind-pairing#CON-001]].
Evidence: `tests/relay_service.rs`, `examples/web_demo.rs`.

#### TEST-029: Claimant-token collision cannot re-claim

Submit an allocator hash and then an existing claimant hash as a new claim.
Require conflict without a `Claimed` effect or state change.

Validates: [[SPEC-001-reusable-blind-pairing#CON-003]].
Evidence: `tests/mailbox.rs`, `tests/relay_service.rs`.

### Assurance gates

The local completion run includes strict formatting and linting, all-feature
tests, Rustdoc, the no-default-feature library, and both dependency graphs.

Seven security mutants are required and locally killed:

1. store plaintext intent metadata;
2. admit a third membership;
3. accept a sequence gap;
4. skip Finished verification;
5. reuse an AEAD nonce;
6. treat authorization as approval; and
7. emit a grant after decline.

The recorded fuzz budgets cover 10,000 wire-recogniser runs, 5,000 mailbox
transition runs, and 1,000 channel-receiver runs.

Detailed evidence lives in
`evidence/completion-audit-local-green-2026-08-16.md`. Local passing evidence
does not satisfy the external production gates.

## Enable, rollback, and operation

Both reference relay binaries keep invitation allocation disabled by default.
The `--enable-conformance-allocation` flag exists only for isolated review and
test environments.

The runtime allocation kill switch rejects new invitations without closing
existing mailboxes. Emergency close deletes queued bodies and retains only
expiry-bounded tombstones.

Disabling a deployment never reopens consumed invitations. Recovery creates a
fresh invitation and fresh cryptographic state.

The reference shells require TLS or WSS termination from the deployment. They
must not be exposed directly to the public Internet.

## Open questions and retained holds

### OQ-001: Human cryptography review — BLOCKING

Owner: named human cryptography reviewer.

The reviewer evaluates CPace revision 21, group arithmetic, transcript binding,
key schedule, Finished values, counters, nonce derivation, and negative vectors.

### OQ-002: Relay deployable placement — RESOLVED

The reference relay lives in this repository with its shared core, wire
contracts, limiter, and conformance suite. A consumer can depend on the library
or speak the wire protocol without changing the relay.

This placement selects no global operator.

Owner disposition: source SPEC-072 v0.3.4. The question no longer blocks
implementation placement.

### OQ-003: Agent grant sealing — BLOCKING FOR LEGACY RETIREMENT

Peer-held CPace state removes the password-equivalent relay premise that
previously blocked sealed agent grants. Production enablement still requires a
human owner to reconcile and retire the legacy agent service.

Owner: agent application owner with the legacy-service reviewer.

### OQ-004: Delegation profile ownership — NON-BLOCKING

Delegation can reuse this channel and define its own payload. It becomes a new
profile when its carrier, approval authority, or displayed intent differs from
the agent profile.

Owner: delegation application owner.

### OQ-005: Profile proximity policy — BLOCKING WHEN APPLICABLE

Owner: each application owner.

Each profile records one disposition: proximity required with a named
mechanism, remote pairing accepted with residual risk, or pairing prohibited.
The credential profile requires a human security decision before production.

### OQ-006: Post-quantum construction — NON-BLOCKING FOR VERSION 1

Owner: future cryptography design review.

Version 1 selects no post-quantum PAKE, PQ-HPKE, lattice ABE, or attribute
authority. Hybrid PQ-PAKE is the closest channel replacement for a human
secret. ML-KEM or PQ-HPKE fits only a carrier that authenticates a public key.
Lattice ABE remains an application-authorization overlay, not a pairing suite.

Selection requires complete encodings, size measurements, independent vectors,
interoperability, downgrade analysis, and human cryptography review.

## Credential/v2 current protocol

This section states the complete current credential/v2 protocol directly.
Trajectory documents provide synthesis evidence and no protocol authority.

### REQ-031: Credential/v2 uses protected admission and distinct human presence

The endpoint SHALL expose separate `CredentialV1Invitation` and
`CredentialV2Invitation` types. Generic bytes, application text, or a caller
version cannot select credential/v2.

The credential/v2 machine carrier SHALL contain no CPace secret, claim bearer,
or `PAIR1-` text. A separate typed presence input supplies raw sixteen-octet
values `C` and `T`.

Only `C` enters CPace. Only `T` authenticates the claimant mailbox admission.
The carrier and presence input cannot substitute for each other.

The allocator SHALL generate one fresh 32-octet mailbox identifier `M`. It
SHALL also generate a fresh 32-octet `carrierCeremonyId`. It SHALL generate
fresh independent `C` and `T` values for each ceremony.

The carrier ceremony ID is the sole credential/v2 ceremony identifier. The
hub, both endpoints, every envelope, the authenticated display authority, and
status recovery use that exact value. No consumer allocates a second ceremony
identifier.

The allocator SHALL commit `T` with this exact construction:

```text
claimCommitment = SHA-256(
  UTF8("cbcl-pairing claim-v2 commitment\u0000") || M || T
)
```

The relay SHALL install exactly one claimant after constant-time commitment
comparison. Wrong bearers preserve mailbox state and return the closed unknown
claim response.

The relay SHALL remain application-unaware. It accepts no application,
profile, PAKE, identity, consent, intent, or payload member.

The CPace `PRS` is raw `C`. The CPace `sid` is raw `M`. Neither `T`, carrier
bytes, nor `PAIR1-` text enters `PRS`.

Both Finished values SHALL verify before application traffic. Every secret is
erased after terminal success or failure.

After Finished, one intent digest SHALL bind the offer, both decisions,
preparation, comparison result, reverse payload, and receipt. Wrong sender,
predecessor, digest, or state is terminal.

Preliminary approval can authorize only the consumer's declared preview
effect. Final approval can authorize only the matching consumer payload.

Credential/v1 retains its existing carrier secret, CPace schedule, display,
wire bytes, and decisions. Neither version retries or relabels the other.

### NFR-023: Credential/v2 work, storage, and typed display stay bounded

V2 admission work SHALL depend only on the addressed mailbox. It SHALL NOT
scan unrelated mailboxes, bodies, expiries, memberships, or limiter entries.

The relay retains at most one 32-octet commitment per waiting v2 mailbox. It
never persists `T` and never exposes either secret through observability.

The v2 mailbox lifetime remains between 60 and 600 seconds. The shared relay
message ceiling remains 70,000 octets.

Control logical bodies contain 1 through 2,048 octets. Large logical bodies
contain 1 through 62,000 octets.

The control padding field contains exactly 4,096 octets. The large padding
field contains exactly 64,512 octets.

Typed transition recognition precedes every owned display allocation. The
recognizer checks authentication, shape, length, count, uniqueness, order, and
aggregate size before cloning.

The exact legacy-handle cap is 33 ASCII octets. The exact room cap is 129
ASCII octets.

A transition contains at most 256 unique rooms in unsigned UTF-8 order. Its
RFC-8785 room-array cap is 33,793 octets.

The compatibility manifest SHALL hash every normative schema, dialect, positive
vector, negative vector, and state vector. Two independent endpoints reproduce
the same bytes and verdicts.

### CON-026: Protected v2 mailbox wire and persisted state

The current v2 relay additions are these deterministic-CBOR variants:

```cddl
client-message /= allocate-v2 / claim-v2
server-message /= allocated-v2 / claimed-v2

allocate-v2 = {
  "type": "allocate-v2",
  "mailbox-id": bstr .size 32,
  "claim-commitment": bstr .size 32,
  ? "ttl-seconds": 60..600
}

claim-v2 = {
  "type": "claim-v2",
  "mailbox-id": bstr .size 32,
  "claim-token": bstr .size 16
}

allocated-v2 = {
  "type": "allocated-v2",
  "mailbox-id": bstr .size 32,
  "membership-token": bstr .size 32,
  "expires-at": uint
}

claimed-v2 = {
  "type": "claimed-v2",
  "mailbox-id": bstr .size 32,
  "membership-token": bstr .size 32,
  "expires-at": uint
}
```

The committed schema contains one closed client union and one closed server
union. Duplicate keys, extras, trailing bytes, and non-canonical encoding
refuse before relay effects.

The pure v2 admission states are `V2Pending(commitment)`, `V2Claimed`, and
`V2Closed`. Legacy mailboxes retain `V1CrowdOnThird`.

A matching claim atomically installs one membership hash, erases the
commitment, persists `V2Claimed`, and emits `claimed-v2`. A failed claim changes
none of those values.

The canonical v2 store record is:

```cddl
mailbox-store-v2 = [
  "cbcl-pairing-mailbox-store/v2",
  bstr .size 32,
  null / 0..999999999,
  uint,
  store-status,
  [1*2 bstr .size 32],
  [* store-sequence],
  [0] / [1, bstr .size 32] / [2] / [3]
]

store-status = [0] / [1] / [2, 0..3]
store-sequence = [
  0..1,
  0..15,
  bstr .size 32,
  1..69632,
  null / bstr .size (1..69632)
]
```

Admission `[0]` is legacy v1. Admission `[1, H]` is pending v2. Admission `[2]`
is claimed v2, and `[3]` is closed v2.

Status `[0]` is waiting. Status `[1]` is paired. Status `[2, reason]` is
terminal with the closed reason enumeration.

A missing v2 admission field never becomes v1. An inconsistent or malformed
v2 record fails startup.

### CON-027: Credential/v2 carrier and CPace channel

The credential/v2 carrier is a separate deterministic-CBOR rule:

```cddl
credential-v2-carrier = {
  "version": 2,
  "profile": "anuna.io/credential/v2",
  "application-context": application-id-v2,
  "profile-version": 2,
  "relay-origin": relay-origin-v2,
  "locator": bstr .size 32,
  "carrier-ceremony-id": bstr .size 32,
  "carrier-nonce": bstr .size 32,
  "claim-commitment": bstr .size 32,
  "relay-expires-at": uint,
  ? "expected-allocator-key": bstr .size 32
}

application-id-v2 = tstr .size (1..2048)
relay-origin-v2 = tstr .size (1..272)
```

The application identifier also satisfies the consumer's canonical HTTPS
grammar. `relay-origin-v2` contains 1 through 272 ASCII octets and satisfies
the consumer's canonical HTTPS-origin grammar: it has no credentials, path,
query, or fragment. The version-1 `relay-origin` rule remains unchanged at
1 through 255 octets and cannot recognise a version-2 carrier.

Extra keys, duplicate keys, trailing bytes, nameplates, secrets, and indirect
locators refuse. The carrier expiry equals the successful allocation response.

`carrierDigest` is SHA-256 over the exact canonical carrier bytes. Both peers
authenticate their independently recognised profile and this digest.

The deterministic-CBOR CPace context is:

```cddl
credential-v2-ci = [
  "cbcl-pairing-ci/credential-v2", 2, "CPACE25519-SHA512-D21",
  "anuna.io/credential/v2", application-id-v2,
  bstr .size 32, bstr .size 32, relay-origin-v2,
  bstr .size 32, bstr .size 32, bstr .size 32,
  ["allocator", "claimant"]
]

credential-v2-ad = [
  "cbcl-pairing-ad/credential-v2", "allocator" / "claimant",
  bstr .size 32 / null, ; expected ceremony-key digest for this role
  bstr .size 32,        ; profileDigest
  bstr .size 32         ; carrierDigest
]
```

The final three `ci` byte strings are mailbox identifier, carrier ceremony
identifier, and claim commitment. The two prior byte strings are profile and
carrier digests.

The complete public-context, transcript, key-schedule, Finished, nonce, and AAD
constructions are stated directly in
[[SPEC-001-reusable-blind-pairing#CON-031]]. No construction or value is
inherited from version 1.

No v1 context, label, key, Finished value, or AAD authenticates a v2 frame.

### CON-028: Credential/v2 envelope and state machine

Every application plaintext uses one of these disjoint deterministic-CBOR
arms:

```cddl
credential-v2-object = credential-v2-control-object / credential-v2-large-object

credential-v2-control-object = {
  0: 2,
  1: 1..8,
  2: bstr .size 32,
  3: 1..2048,
  4: bstr .size 4096
}

credential-v2-large-object = {
  0: 2,
  1: 0 / 9 / 10,
  2: bstr .size 32,
  3: 1..62000,
  4: bstr .size 64512
}
```

Kinds are `offer`, `intent-approve`, `intent-decline`, `preparation`,
`comparison-confirmed`, `binding-confirmed`, `refusal`, `final-approve`,
`final-decline`, `payload`, and `receipt`.

Only `offer`, `payload`, and `receipt` use the large arm. Every other kind uses
the control arm. The receipt needs the large arm for the closed signed hub
status that authorizes installation.

The receipt logical body is this deterministic-CBOR map:

```cddl
credential-v2-receipt-body = {
  "carrier-ceremony-id": bstr .size 32,
  "predecessorDigest": bstr .size 32,
  "final-status-jws": tstr .size (1..8192),
  "final-status-digest": bstr .size 32
}
```

The JWS text contains only compact-JWS ASCII. The digest is raw SHA-256 over
the JWS payload's exact RFC-8785 octets. Unknown members, another ceremony,
another predecessor, invalid ASCII, or a digest mismatch refuse installation.

Field 2 contains one `intentDigest`. Field 3 contains the logical body length.
The remaining field-4 bytes are zero.

For a recognised proof-free offer core:

```text
offerCoreDigest = SHA-256(RFC8785(OfferCoreV2))
intentDigest = SHA-256(
  UTF8("selfsame credential/v2 intent\u0000") || offerCoreDigest
)
```

Every successor repeats the same intent digest. Every successor logical body
also carries `predecessorDigest`, the exact prior object content hash defined
by [[SPEC-001-reusable-blind-pairing#CON-031]]. The Selfsame consumer owns
the other nine closed logical-body grammars in its current parent. The shared
endpoint owns their envelope, canonical bytes, content hash,
predecessor equality, and state transition.

The session projection is:

```text
begin -> offer
offer -> intent-approve | intent-decline
intent-approve -> preparation
preparation -> comparison-confirmed | binding-confirmed | refusal
comparison-confirmed | binding-confirmed -> final-approve | final-decline
final-approve -> payload
payload -> receipt | refusal
intent-decline | final-decline | receipt | refusal -> terminal
```

Allocator sends offer, comparison, binding, receipt, and allocator refusal.
Claimant sends both decisions, preparation, payload, and claimant refusal.

Each control binds sender, carrier ceremony, kind, intent digest, body digest,
body length, and predecessor. Only exact retransmission is idempotent.

### CON-029: Opaque authenticated credential/v2 display

`DisplayIntent` and `DisplayField` SHALL have private fields. Public consumers
receive only borrowed read access.

Credential/v2 SHALL NOT use generic `DisplayField` values. It SHALL NOT expose
the wire `authority_summary` on its consent surface.

The credential/v2 endpoint constructor SHALL take a separate borrowed
`CredentialV2IntentAuthority` supplied by the consumer. It SHALL expose typed
read-only accessors for authenticated application ID, HTTPS origin, and relay
origin. It SHALL also expose the carrier ceremony ID, account provenance,
permissions, device binding, exact-pair TOFU state, transition, and signed
offer-core digest.

For the Selfsame profile, `CredentialV2IntentInput` is constructed only from
the completely recognised offer logical body: cbcl-bus SPEC-053 0.17.3-draft
CON-012's `signed-offer-v2` and its exact `OfferCoreV2`. The other ten body
kinds cannot construct or amend an intent input. The consumer's nine successor
body grammars are Selfsame SPEC-008 0.5.3-draft CON-987.

The profile first parses one bounded peer `CredentialV2IntentInput`. Before any
display allocation, it SHALL require byte equality between every overlapping
peer value and the separate authority input. It SHALL also require the peer
intent digest to bind the authority's signed offer-core digest.

The injected consumer verifier receives immutable references to the parsed
peer input and separate authority input. It returns only a closed verdict.

The verifier cannot return, append, replace, or mutate display data. After
success, only the profile constructs one owned `CredentialV2Display`. Every
displayed value is copied from the authority input. No displayed value is
copied from the peer input.

The display contains authenticated application ID, HTTPS origin, relay origin,
account assertion provenance, permissions, device binding, and exact-pair TOFU
state. It also contains one closed transition.

```text
AccountTransition = NoTransition
                  | PathAToB {
                      legacyHandle,
                      legacyKeyDigest,
                      migrationRooms,
                      roomSetDigest,
                      migrationSnapshotDigest,
                      snapshotNonce
                    }
```

The application ID and transition come from the authenticated authority input.
They are never copied from an unchecked counterpart claim.

The first display can include only authenticated transition data. The later
display adds the consumer's locally derived DID and fingerprint.

The room grammar is:

```text
LegacyHandle = "@" 1*32( %x61-7A / DIGIT / "_" / "-" )

CbclSymbolChar = ALPHA / DIGIT / "_" / "-" / "." / "/" / "!" /
                 "?" / "+" / "*" / "<" / ">" / "=" / "@"
RoomShape = "@" 1*( CbclSymbolChar )
CanonicalRoomText = RoomShape with 2..129 ASCII octets
```

The serializer does not escape `/`. Unknown shape, excessive length,
duplicate rooms, wrong order, excessive count, and excessive aggregate refuse
before display construction.

The profile does not decide account authority, room eligibility, migration,
DID derivation, grant issuance, or browser persistence.

### CON-030: Credential/v2 endpoint checkpoints preserve in-flight authority

`EndpointCheckpointV2` SHALL have private fields and no `Debug`, `Clone`,
generic serialization, or plaintext export. The protocol library SHALL seal
and open it only with a consumer-supplied 32-octet wrapping key.

The checkpoint key is HKDF-SHA512 over that wrapping key. Its salt is the raw
carrier ceremony ID. Its info is deterministic CBOR containing the label
`cbcl-pairing checkpoint key/v2`, endpoint role, and application context.

The sealed checkpoint has this deterministic-CBOR outer shape:

```cddl
credential-v2-checkpoint = [
  "cbcl-pairing-endpoint-checkpoint/v2",
  2,
  "allocator" / "claimant",
  "anuna.io/credential/v2",
  bstr .size 32,
  uint,
  null / uint,
  bstr .size 12,
  bstr .size (1..69632)
]
```

The integer is checkpoint generation. The following member is an absolute
expiry or `null`. `null` applies only after a claimant durably sends its
payload and before receipt. The authenticated application status can outlive
the relay mailbox. The nonce is fresh CSPRNG
output for AES-256-GCM. The preceding seven members form its exact AAD.

The encrypted inner state contains the exact role, carrier, mailbox identifier,
membership bearer, peer key, local signing state, monitor projection, and
transcript. It also contains traffic keys, IVs, counters, intent digest,
predecessor hashes, accepted decisions, and any cached exact outbound frame.
It contains no consumer key, derived application key, issuer key, or grant key.

An allocator checkpoint before Finished MAY contain its live `C` and `T`.
The first checkpoint after claimant admission erases `T`. The first checkpoint
after both Finished values erases `C`. No claimant checkpoint contains either.

The library recognizer SHALL require complete deterministic-CBOR decoding and
the exact outer bindings. It SHALL require a strictly positive generation. The
state SHALL be unexpired or use the permitted post-payload `null` value.
It SHALL reject extras, trailing bytes, wrong roles, wrong applications, wrong
ceremonies, changed generations, or failed AEAD before endpoint construction.

The allocator SHALL checkpoint from carrier allocation until terminal receipt.
The claimant SHALL first checkpoint after final approval and before its first
consumer identity effect. A preliminary decision never becomes a checkpointed
effect capability.

Before a state-changing outbound frame, the endpoint SHALL expose its next
checkpoint and exact cached frame as one ordered effect. The consumer persists
the checkpoint atomically before sending the frame. Resume retransmits only
that cached frame and advances only through ordinary idempotent recognition.

An inbound replay after recovery either reproduces the same next effect or
refuses. It cannot repeat a consumer decision, payload construction, receipt,
or application effect. An old checkpoint can cause refusal but cannot authorize
a new transition against a peer or hub that advanced.

Terminal decline, pre-payload refusal, pre-payload expiry, and verified receipt
erase the checkpoint. Relay or offer expiry after durable payload send does not
erase the claimant checkpoint. It remains sealed and non-authorizing until a
verified receipt, explicit application unlink, or root-lifecycle purge. The
verified receipt can use the ordinary or recovered path.
The allocator wrapping key derives from its persisted installation seed. The
claimant wrapping key derives inside unlocked custody with the application and
carrier ceremony as context. Neither raw wrapping key enters the checkpoint.

### CON-031: Credential/v2 cryptography and object hashing are complete

The exact deterministic-CBOR public context is:

```cddl
credential-v2-public-context = [
  "cbcl-pairing-public-context/credential-v2", 2,
  "CPACE25519-SHA512-D21", "anuna.io/credential/v2",
  application-id-v2,
  bstr .size 32, ; profileDigest
  bstr .size 32, ; carrierDigest
  relay-origin-v2,
  bstr .size 32, ; mailboxId
  bstr .size 32, ; carrierCeremonyId
  bstr .size 32, ; claimCommitment
  bstr .size 32 / null, ; expectedAllocatorKey
  null                  ; expectedClaimantKey is absent in this version
]

credential-v2-aad = {
  "v": 2,
  "direction": 0..1,
  "counter": uint,
  "th": bstr .size 64
}
```

Every comment above names the semantic value in that exact position. The
public context contains exactly thirteen members. Direction `0` is allocator
to claimant and direction `1` is claimant to allocator.

Let `publicContext`, `allocatorCpaceFrame`, and `claimantCpaceFrame` be their
exact deterministic-CBOR byte strings. Let `ISK` be the CPace shared secret.
The constructions are:

```text
TH = SHA-512(DETERMINISTIC-CBOR([
  bstr(publicContext),
  bstr(allocatorCpaceFrame),
  bstr(claimantCpaceFrame)
]))

PRK      = HKDF-Extract-SHA512(empty-octet-string, ISK)
KC_A     = HKDF-Expand-SHA512(PRK, ASCII("pairing-credential-v2 kc A") || TH, 32)
KC_B     = HKDF-Expand-SHA512(PRK, ASCII("pairing-credential-v2 kc B") || TH, 32)
KEY_A_B  = HKDF-Expand-SHA512(PRK, ASCII("pairing-credential-v2 key A-B") || TH, 32)
KEY_B_A  = HKDF-Expand-SHA512(PRK, ASCII("pairing-credential-v2 key B-A") || TH, 32)
IV_A_B   = HKDF-Expand-SHA512(PRK, ASCII("pairing-credential-v2 iv A-B") || TH, 12)
IV_B_A   = HKDF-Expand-SHA512(PRK, ASCII("pairing-credential-v2 iv B-A") || TH, 12)
EXPORTER = HKDF-Expand-SHA512(PRK, ASCII("pairing-credential-v2 exporter") || TH, 32)

Finished_A = HMAC-SHA-512(
  KC_A, ASCII("pairing-credential-v2 finished A") || TH
)
Finished_B = HMAC-SHA-512(
  KC_B, ASCII("pairing-credential-v2 finished B") || TH
)
```

`ASCII(...)` contributes exactly the displayed ASCII octets and no terminator.
`empty-octet-string` has length zero. The seven HKDF outputs have lengths 32,
32, 32, 32, 12, 12, and 32 octets in the order shown. Both Finished values
contain 64 octets and verify in constant time before application traffic.

Each traffic direction starts at counter zero and accepts only the exact next
unsigned 64-bit counter. The 12-octet nonce is its direction IV XOR the
counter encoded as a 96-bit big-endian value with four leading zero octets.
Counter exhaustion, reuse, duplication, or a gap is terminal before decryption.

The AES-256-GCM AAD is the exact deterministic-CBOR encoding of
`credential-v2-aad`. The `th` value is raw `TH`. A sender encrypts with its
role-specific key, IV, direction, and counter. A receiver derives the same
values and accepts no caller-supplied nonce or AAD.

For every completely recognised `credential-v2-object`, define:

```text
objectContentHash = SHA-256(exact canonical credential-v2-object bytes)
```

The exact bytes include fields 0 through 4, the selected fixed-size padding,
and every required zero padding octet. Every successor logical body except the
offer carries that raw 32-octet value as `predecessorDigest`. Equality is constant-time and
is checked before profile parsing, display, decision, or effect dispatch.

No trajectory document, version-1 rule, implicit library default, prose label,
or caller-selected algorithm supplies any value in this contract.

### CON-032: A profile may recover only an independently authenticated receipt

The endpoint SHALL expose `recover_receipt` only while a recognised claimant
checkpoint is in the `payload -> receipt` state. Its input is one exact
credential/v2 receipt logical body and one private
`CredentialV2RecoveredReceiptAuthority`. The library produces that authority
internally only after the registered consumer verifier returns success.

The authority type has private fields and no public constructor, clone,
serialization, deserialization, or boolean conversion. Its fields bind the
application context, carrier ceremony ID, intent digest, payload
`objectContentHash`, final-status digest, and receipt-body digest. The consumer
verifier receives immutable inputs and returns only a closed success or refusal.
It SHALL independently authenticate its application status source.

`recover_receipt` SHALL recompute the receipt body, require the exact retained
ceremony, intent, and payload predecessor, consume the authority once, and run
the ordinary `payload -> receipt -> terminal` reducer. It creates no alternate
accepted state and cannot recover an offer, decision, preparation, refusal, or
payload. A mismatch, reused authority, wrong checkpoint state, or unregistered
profile refuses and leaves the checkpoint pending.

This adapter authenticates no application status itself. The Selfsame consumer
owns that signature, origin, commitment, and persistence verification in its
current parent. Generic callers cannot construct the authority from receipt
bytes or an unchecked network result.

### ADR-024: Reusable protocol types carry authentication, not application policy

Protected admission, channel state, and typed display construction belong to
the reusable protocol. Application account and migration decisions remain in
the consumer verifier.

The verdict-only verifier prevents the application from injecting display
text. Private display fields prevent later substitution by a UI caller.

Separate carrier and presence types make co-presence a protocol property. They
also keep the blind relay free of application semantics.

### TEST-060: Protected v2 mailbox admission is complete

Exercise exact, wrong, missing, cross-mailbox, repeated, v1, and malformed claim
bearers. Only the exact bearer installs one claimant and erases the commitment.

Restart from every v1 and v2 admission state. Malformed or inconsistent v2
state fails startup.

Inject crashes before write, during write, before rename, after rename, and
before response. Restart yields exactly pending or claimed state.

Inspect snapshots, stores, heap retention, logs, metrics, traces, and errors.
No claim bearer survives, and no commitment survives successful admission.

### TEST-061: Credential/v2 cryptography and state are independently reproducible

Two independent endpoints reproduce carrier, context, transcript, key schedule,
Finished, AAD, ciphertext, object, content hash, and every terminal verdict.

Mutate each carrier, context, role, digest, label, counter, sender, predecessor,
kind, decision, and padding member independently. Every mutation fails before
an unauthorized effect.

Only exact retransmission is idempotent. Conflicting decisions, reordering,
late frames, and post-terminal frames fail closed.

### TEST-062: Typed display contains only authenticated bounded values

Compile-fail fixtures attempt public display construction, generic v2 fields,
verifier-returned display data, transition replacement, and serialized
reconstruction. Every attempt fails.

A recording verifier receives immutable peer and authority inputs. Refusal
emits no display, and success reproduces only authenticated authority bytes.

Give the peer and authority different application IDs, origins, relays,
provenance, permissions, device bindings, transitions, offer-core digests, and
intent digests one at a time. Every mismatch refuses before display allocation.

Mutate application, origin, relay, provenance, permissions, binding,
transition, room, digest, nonce, order, and cap. Every mutation refuses before
display.

Verify the screen has no peer `authority_summary`. Verify every displayed
application and transition value comes from authenticated typed input.

Construct every room-symbol branch and 256 distinct maximum rooms. Require the
33,793-octet array and exact borrowed accessors.

### TEST-063: Compatibility, bounds, and current authority are singular

Re-run every base TEST-001 through TEST-029 outcome. Credential/v1 bytes,
hashes, displays, stores, frames, and verdicts remain identical.

Accept control lengths 1, 23, 24, 255, 256, 2,047, and 2,048. Refuse 0, 2,049,
4,095, and 4,096.

Accept large lengths through 62,000 and refuse 62,001. Require exact encoded
object lengths for every integer-head boundary.

Require offer, payload, and receipt to use only the large arm. Require every
other kind to use only the control arm. A receipt encoded as control refuses.

Require one current credential/v2 protocol section, one current consumer
pointer, one current hub pointer, and one current test set.

The current test set contains TEST-001 through TEST-029 and TEST-060 through
TEST-067. No trajectory test supplies current authority.

The current consumer is Selfsame SPEC-008 0.5.3-draft. The current safety
authority is Selfsame SPEC-007 0.3.1-draft. The current hub design is cbcl-bus
SPEC-053 0.17.3-draft.

All four coordinated parents record the same generation metadata and review
set.

A qualifying reviewer uses another model family and a fresh session. The
report records model, authentication path, session, and Circus attempt.

A fresh Tier-1 PASS authorizes only the Elephant SPL and test-first plan. It
authorizes no production allocation, release, or deployment.

### TEST-064: One carrier ceremony identifier governs every v2 binding

**Validates:** [[SPEC-001-reusable-blind-pairing#REQ-031]],
[[SPEC-001-reusable-blind-pairing#CON-027]], and
[[SPEC-001-reusable-blind-pairing#CON-029]].

Generate one carrier with a fresh carrier ceremony ID. Require the CPace
context, every envelope, authority input, display, offer, hub command, status,
and receipt to carry that exact 32-octet value.

Place the signed immutable hub status in the receipt's large logical body.
Accept the 8,192-octet status bound with its receipt framing. Refuse a control
arm, a body above 62,000 octets, or a changed status digest.

Require the exact receipt map, carrier ceremony, predecessor, compact-JWS
ASCII, and raw payload digest. Refuse every missing, extra, duplicated, or
non-canonical member before a receipt effect.

Mutate each occurrence independently. Require refusal before display,
decision, payload, status rebind, or identity effect.

Add the retired `ceremony-id` member, omit `carrier-ceremony-id`, or add a
consumer-generated second identifier. Require complete carrier recognition to
refuse with no relay allocation or endpoint state.

Re-run carrier canonical-CBOR roundtrip and fuzz cases. Require duplicate keys,
extras, trailing bytes, wrong lengths, and non-canonical encodings to refuse.

### TEST-065: Endpoint recovery cannot duplicate authority or effects

**Validates:** [[SPEC-001-reusable-blind-pairing#CON-030]].

Checkpoint the allocator at every state from carrier allocation through
receipt. Checkpoint the claimant after final approval and before each later
transition. Restore each role with the exact key and bindings.

Crash before checkpoint persistence, after persistence, before send, after
send, before receive persistence, and after receive persistence. Require exact
cached retransmission, one monotonic state projection, and one terminal receipt.

Mutate each outer member, ciphertext octet, wrapping key, role, application,
ceremony, generation, expiry, counter, monitor state, predecessor, and cached
frame. Require refusal before endpoint construction or a protocol effect.

Restore an old valid checkpoint against every advanced peer state. Require
only exact idempotent replay or terminal refusal. Never repeat preliminary or
final approval, payload construction, consumer identity work, or receipt.

Fill the sealed ciphertext to 69,632 octets and accept it. Refuse zero length,
69,633 octets, extra members, trailing bytes, non-canonical CBOR, nonce reuse,
and expired state.

Inspect checkpoints, logs, errors, traces, heap retention, and terminal erasure.
No wrapping key, presence token, application key, issuer key, or grant key
survives outside its declared boundary.

### TEST-066: Every credential/v2 cryptographic byte has one construction

**Validates:** [[SPEC-001-reusable-blind-pairing#CON-027]],
[[SPEC-001-reusable-blind-pairing#CON-028]], and
[[SPEC-001-reusable-blind-pairing#CON-031]].

Two independent implementations consume only the current parent. They
reproduce the thirteen-member public context, `TH`, and `PRK`. They reproduce
all seven HKDF outputs, both Finished values, and every directional nonce. They
also reproduce exact AAD bytes, sealed frames, content hashes, and predecessors.

Exercise counters zero, one, 255, 256, the largest unsigned 64-bit value, and
exhaustion. Mutate one public-context position, nullable key, role, label byte,
output length, frame order, salt octet, AAD key, direction, counter octet,
padding octet, or predecessor octet. Every mutation refuses before profile
parsing or effects.

Scan the current parent for each construction identifier. Require exactly one
normative definition and no dependency on a trajectory document or a v1
context, label, key, Finished value, nonce, or AAD.

### TEST-067: Recovered receipt authority cannot bypass the reducer

**Validates:** [[SPEC-001-reusable-blind-pairing#CON-032]].

At every state other than claimant `payload -> receipt`, call
`recover_receipt` with a real authority and exact receipt. Require refusal and
no state change. At the correct state, require the byte-identical ordinary and
recovered receipt paths to reach the same terminal state and erase the same
checkpoint.

Attempt to construct, clone, serialize, replay, or substitute
`CredentialV2RecoveredReceiptAuthority`. Compile-time or recognition failure
precedes transition. Mutate each bound ceremony, intent, payload predecessor,
final-status digest, and receipt digest independently; require the checkpoint
to remain pending and no consumer effect to repeat.

## Production gates

Production allocation remains prohibited until all applicable gates have
durable evidence:

1. fresh-context adversarial specification and code review;
2. human cryptography review with a second CPace group implementation;
3. two independently operated relay deployments for both real profiles;
4. independent endpoint disposition for all public vectors;
5. profile-specific human policy decisions; and
6. specification-owner production-enablement decision.

No passing CI job, conformance flag, local implementation audit, or draft
status change substitutes for these dispositions.

## Reading paths

- Reviewer: [[SPEC-001-reusable-blind-pairing#Failure modes]] →
  [[SPEC-001-reusable-blind-pairing#Architecture decisions]] →
  [[SPEC-001-reusable-blind-pairing#Open questions and retained holds]].
- Implementer: one [[SPEC-001-reusable-blind-pairing#Contracts]] entry → its
  `Implements` links → its `Verified by` links.
- Application owner: [[SPEC-001-reusable-blind-pairing#REQ-011]] →
  [[SPEC-001-reusable-blind-pairing#CON-005]] → one profile →
  [[SPEC-001-reusable-blind-pairing#TEST-010]].
- Operator: [[SPEC-001-reusable-blind-pairing#CON-002]] →
  [[SPEC-001-reusable-blind-pairing#CON-003]] →
  [[SPEC-001-reusable-blind-pairing#CON-008]] →
  [[SPEC-001-reusable-blind-pairing#Enable, rollback, and operation]].

## Amendment Channels

Amendable by: the `cbcl-pairing` specification owner and affected application
owners.

Through: a reviewed, merged revision of this specification with updated assets,
tests, evidence, and compatibility disposition.

Not amendable by: issue comments, chat messages, code review remarks, source
comments, implementation behaviour, test fixtures, or dependency updates.

Hard stops: [[SPEC-001-reusable-blind-pairing#REQ-002]],
[[SPEC-001-reusable-blind-pairing#REQ-005]],
[[SPEC-001-reusable-blind-pairing#REQ-008]],
[[SPEC-001-reusable-blind-pairing#REQ-009]],
[[SPEC-001-reusable-blind-pairing#REQ-013]],
[[SPEC-001-reusable-blind-pairing#REQ-014]],
[[SPEC-001-reusable-blind-pairing#REQ-015]],
[[SPEC-001-reusable-blind-pairing#NFR-009]],
[[SPEC-001-reusable-blind-pairing#NFR-010]],
[[SPEC-001-reusable-blind-pairing#NFR-011]],
[[SPEC-001-reusable-blind-pairing#NFR-012]], and every item under
[[SPEC-001-reusable-blind-pairing#Production gates]].

No channel can waive a hard stop without a new specification version and the
required Tier-1 review.

## Exclusions

- The protocol does not hide timing, size, or network-address metadata from the
  selected relay operator.
- A malicious operator can deny service, delay delivery, or crowd an
  invitation. Anonymous-client work amplification violates
  [[SPEC-001-reusable-blind-pairing#NFR-009]],
  [[SPEC-001-reusable-blind-pairing#NFR-010]],
  [[SPEC-001-reusable-blind-pairing#NFR-011]], or
  [[SPEC-001-reusable-blind-pairing#NFR-012]].
- Version 1 does not claim post-quantum security.
- Version 1 does not define an attribute authority, revocation system, or
  general authorization policy.
- `cbcl-rs` contains no pairing-specific protocol or cryptography.
- The reference relay shells do not terminate TLS or export metrics.
- This draft does not claim formal cryptographic proof or production approval.

## Changelog

<details>
<summary>Revision history — 0.1.0 → 0.5.2-draft</summary>

- 0.5.2-draft — states the complete credential/v2 public context, key
  schedule, Finished, nonce, AAD, content-hash, and authenticated receipt
  recovery constructions directly. Reconciles the v2 relay-origin bound. No
  production action is authorized.

- 0.5.1-draft — names one allocator-generated carrier ceremony ID as the sole
  credential/v2 ceremony identifier. Adds sealed endpoint checkpoints. Removes
  the unused rendezvous pointer and coordinates Selfsame SPEC-007 directly. No
  production action is authorized.

- 0.5.0-draft — restates credential/v2 protocol and current consumer authority
  directly after the pointer-only review rejection.

- 0.4.0-draft — preserves the unchanged credential/v2 protocol body through
  0.4.8 and moves the current consumer pointer into this parent. The
  coordinated Tier-1 review remains open. No code or deployment is authorized.

- 0.2.0 — added work-amplification failure analysis, performance limits,
  indexed relay accounting, clock clamping, limiter diversity handling, and
  review-drift corrections.

- 0.1.0 — created the repository-local specification from SPEC-072 v0.3.4,
  exact local protocol assets, completed implementation evidence, and retained
  production holds.

</details>

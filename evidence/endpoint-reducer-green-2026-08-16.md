# Endpoint reducer Green Gate — 2026-08-16

Focused command:

```text
cargo test --test endpoint
```

Result: 7 passed, 0 failed, 0 ignored.

Whole-tree and static commands after the component-status switch:

```text
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Result: strict Clippy passed. Every implemented component test passed; the
aggregate Red Gate advanced to `application-profiles`, the next unimplemented
component.

Implemented boundary:

- a persistable secret-free invitation record atomically binds the exact
  invitation, mailbox, peer CPace frame, and public transcript before the first
  online guess; exact resume is accepted and alternate resume spends it;
- `Unknown` retains only bounded exact controls and has no confirmation, role
  cast, display, decision, or application effect;
- local and peer Finished controls first receive CBCL verdicts, then the peer
  HMAC is confirmed, and only then can the allocator emit the encrypted inert
  role opener;
- the opener uses the two CPace-frame ceremony keys and exact session dialect
  pin; expected invitation key digests are checked when their role keys become
  available;
- every sealed frame passes directional AEAD, deterministic inner recognition,
  body binding, R4, and R6 before reducer effects;
- only an approved decision for the accepted intent digest permits one payload;
- exact decision replay is effect-free, including exact local and received
  decline replay after erasure (the receiver retains only the authenticated
  frame digest), while two individually valid decision siblings terminate
  without releasing a payload; and
- decline, Finished failure, CBCL violation, counter/tag failure, digest
  mismatch, and decision conflict spend the invitation and drop all
  secret-bearing key/channel state.

The tests include a peer-signed but HMAC-invalid Finished value and a malicious
claimant that sends valid approval and decline siblings at contiguous AEAD
counters. These distinguish cryptographic confirmation from R4 validity and
CBCL causality from atomic endpoint decision uniqueness.

This is non-production conformance evidence. Human cryptographic and
independent interoperability reviews remain mandatory release gates.

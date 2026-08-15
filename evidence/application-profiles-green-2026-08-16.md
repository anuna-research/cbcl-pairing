# Application profiles Green Gate — 2026-08-16

Focused commands:

```text
cargo test --test profiles
cargo test --test endpoint
cargo clippy --all-targets --all-features -- -D warnings
```

Result: 4 profile tests and 8 endpoint tests passed; strict Clippy passed.
The complete suite passed every implemented component and stopped only at the
next aggregate Red Gate, `relay-service`.

Implemented boundary:

- `ApplicationProfile` is a public endpoint-local injection point, not an
  application registry or relay configuration surface;
- fixed agent, credential, and synthetic profiles own their application IDs,
  carrier/locator/entropy contracts, exact actions, claim recognisers, display
  fields, payload types, semantic bindings, and grant verifiers;
- agent and credential profiles require consumer-supplied authoritative grant
  verifiers; the shared library does not implement SPEC-061 or
  SPEC-004/PROTO-004 grant authority;
- every profile claim and grant body is deterministic CBOR with exact keys,
  bounds, no duplicates, no trailing data, and canonical re-encoding;
- the reducer requires a profile matching the invitation, performs profile
  recognition before intent display, retains only a profile binding digest,
  and emits an `AuthorisedGrant` only after exact-intent approval and one
  successful profile-verifier invocation;
- the synthetic profile leaves the relay binary source, shared CDDL, mailbox,
  limiter, and observability sources at their pinned byte hashes; and
- an always-authorized synthetic verifier cannot bypass Finished, intent,
  approval, decline, invitation state, or endpoint effects. After valid pairing
  and approval it accepts once without changing pairing state.

This is non-production conformance evidence. Application-specific verifier
review, the human cryptography gate, and independent interoperability remain
mandatory.

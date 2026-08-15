# TEST-018 independent endpoint evidence — 2026-08-16

Result: local cross-language conformance gate passed.

The independently written `tools/reference_endpoint.py` uses no Rust code,
cbcl-rs, CBOR package, or S-expression package. It independently implements
deterministic CBOR, RFC 9804 typed canonical S-expressions, Ed25519 signing and
verification, the transcript and HKDF-SHA-512 schedule, Finished values,
directional AES-256-GCM, and causal/terminal classifications. The existing
published CPace revision-21 fixture supplies the post-PAKE ISK; TEST-016 remains
the separate gate for CPace group arithmetic and human cryptographic review.

`cargo test --all-features --test independent_endpoint` passed. The Python and
Rust endpoints agreed on every emitted byte for:

- invitation, ceremony identifier, CI, both AD values, and public context;
- both nested CPace messages, signed controls, content addresses, and frames;
- transcript hash, both Finished values, controls, content addresses, and frames;
- exporter, both directional ciphertexts, and both sealed frames;
- the agent and credential invitation encodings;
- the exact role-cast opener, intent, approval, and payload controls, causal
  hashes, sealed plaintexts, counters, ciphertexts, and frames;
- identical session-ready, display-intent, approve, and deliver-grant events,
  with one authorised synthetic grant;
- fixed-time expiry, secret erasure, and its terminal classification;
- valid, unknown-predecessor, and adjacent-body CBCL verdicts; and
- bad-Finished, replay, gap, wrong-direction, and bad-tag terminal results.

`cargo test --all-features` then passed the complete crate suite, including the
same TEST-018 gate. This is implementation evidence, not a human cryptographic,
adversarial, profile, named integration-reviewer, or production-enablement
disposition. CPace group arithmetic remains deliberately owned by TEST-016.

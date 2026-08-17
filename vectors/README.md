# Interoperability vectors

This directory will contain deterministic public vectors for every SPEC-072
endpoint boundary.

Each vector fixes role, invitation bytes, inbound frames, random octets, and
time. It also fixes outbound bytes, verdicts, effects, and terminal state.

The normative dialect byte and canonical hashes already run in
`tests/dialects.rs`. `tests/cpace.rs` records and checks the CPace255 generator,
exchange, shared-point, intermediate-session-key, and X25519 input vectors from
[CPace draft revision 21, Appendix B](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21#appendix-B).
Those are draft-author vectors, not independently generated vectors. An
independent CPace vector source and the required human cryptography review
remain absent.
## Independent endpoint vector

`tools/reference_endpoint.py` is the executable public TEST-018 vector. It is
an independently implemented Python endpoint using a local deterministic-CBOR
encoder, RFC 9804 S-expression encoder, Ed25519 verification, HKDF-SHA-512,
HMAC-SHA-512, and AES-256-GCM. `tests/independent_endpoint.rs` runs it and
requires byte equality with the Rust endpoint for the invitation, contexts,
CBCL controls and content hashes, CPace and Finished frames, transcript,
Finished values, exporter, and both sealed directions. It also compares the
closed rejection and terminal classifications.

The post-CPace ISK is the draft revision-21 CPace Appendix B.1 vector already
checked by TEST-016; the Python endpoint deliberately does not duplicate CPace
group math. This keeps the assurance boundary explicit: TEST-016 checks the
implementation against the draft-author PAKE vectors, while TEST-018 covers
the complete protocol around its agreed ISK. Neither substitutes for the open
independent-vector and human-review gates.

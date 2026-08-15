# Interoperability vectors

This directory will contain deterministic public vectors for every SPEC-072
endpoint boundary.

Each vector fixes role, invitation bytes, inbound frames, random octets, and
time. It also fixes outbound bytes, verdicts, effects, and terminal state.

The normative dialect byte and canonical hashes already run in
`tests/dialects.rs`. Cryptographic vectors remain intentionally absent until
their independent source and draft revision are recorded.
## Independent endpoint vector

`tools/reference_endpoint.py` is the executable public TEST-018 vector. It is
an independently implemented Python endpoint using a local deterministic-CBOR
encoder, RFC 9804 S-expression encoder, Ed25519 verification, HKDF-SHA-512,
HMAC-SHA-512, and AES-256-GCM. `tests/independent_endpoint.rs` runs it and
requires byte equality with the Rust endpoint for the invitation, contexts,
CBCL controls and content hashes, CPace and Finished frames, transcript,
Finished values, exporter, and both sealed directions. It also compares the
closed rejection and terminal classifications.

The post-CPace ISK is the published revision-21 CPace vector already checked by
TEST-016; the Python endpoint deliberately does not duplicate CPace group math.
This keeps the assurance boundary explicit: TEST-016 covers PAKE arithmetic,
while TEST-018 covers the complete protocol around its agreed ISK.

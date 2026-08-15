# Interoperability vectors

This directory will contain deterministic public vectors for every SPEC-072
endpoint boundary.

Each vector fixes role, invitation bytes, inbound frames, random octets, and
time. It also fixes outbound bytes, verdicts, effects, and terminal state.

The normative dialect byte and canonical hashes already run in
`tests/dialects.rs`. Cryptographic vectors remain intentionally absent until
their independent source and draft revision are recorded.


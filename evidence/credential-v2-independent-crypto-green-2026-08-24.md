# Credential/v2 independent cryptographic oracle — 2026-08-24

Target: [[SPEC-001-reusable-blind-pairing#TEST-066]].

`tests/support/credential_v2_oracle.py` uses Python standard-library SHA-512,
HMAC, HKDF expansion, deterministic-CBOR primitives, and `cryptography` X25519
and AES-GCM. It imports no cbcl-pairing code. The Rust unit test supplies only
fixed public inputs, CPace scalars/shares, and plaintext.

The two implementations reproduce the CPace ISK, transcript hash, HKDF PRK,
both confirmation keys, both traffic keys, both IVs, exporter, both Finished
values, allocator-to-claimant counter-zero AAD and nonce, and the first sealed
ciphertext.

`cargo test --lib
test_066_python_oracle_reproduces_complete_v2_schedule_and_first_frame` passes.
`cargo clippy --all-targets --all-features -- -D warnings` and
`git diff --check` also pass.

A deliberate production mutation changed the allocator-to-claimant HKDF label
from `key A-B` to `key A-C`. The focused oracle test failed on the derived key,
then passed again after the mutation was removed.

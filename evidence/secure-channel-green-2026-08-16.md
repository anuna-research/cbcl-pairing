# Secure-channel implementation evidence

- Date: 2026-08-16
- Contract: `CON-004` after CPace ISK
- Commands:
  - `cargo test --test channel`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets`

## Result

Seven secure-channel tests pass. The implementation matches independently
calculated SHA-512 transcript, HKDF-SHA-512, role-A Finished, role-B Finished,
and exporter bytes. It uses exact context/A-frame/B-frame transcript order and
the seven distinct labels from `CON-004`.

Both AES-256-GCM directions round-trip with independent keys, IVs, and
contiguous counters. The deterministic-CBOR AAD and IV-XOR-big-endian-counter
nonce match fixed expected bytes. Empty and oversized local plaintexts do not
consume a nonce; the maximum 69,556-octet plaintext produces the exact 69,572
octet ciphertext ceiling.

Wrong secrets, changed transcript context, and corruption of either Finished
value prevent channel activation. Replay, gaps, wrong direction, undersized
ciphertext, an unexpected frame type, and authentication failure return a
specific first error and make the receive channel terminal. Directional keys
produce different ciphertext for identical plaintext and counter values.

The implementation pins the current RustCrypto line used here: `aes-gcm`
0.11.0, `hkdf` 0.13.0, `hmac` 0.13.0, and `sha2` 0.11.0. Secret schedule
material, traffic keys, IVs, and exporter bytes use zeroizing storage, and
pending/confirmed channel debug output is redacted.

All prior component tests remain green. The aggregate Red Gate now stops at
`cbcl-protocol`.

## Scope boundary

This satisfies the implementer-owned `secure-channel` slice and local
cryptographic portions of `TEST-006`, `TEST-008`, `TEST-011`, and `TEST-016`.
Persistent invitation consumption and mailbox closure are endpoint/relay
integration work. The independent endpoint and named human cryptography review
remain mandatory later gates; this evidence does not approve production use.

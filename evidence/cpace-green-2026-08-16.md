# CPace255 revision-21 implementation evidence

- Date: 2026-08-16
- Pinned construction: `CPACE-X25519-SHA512`,
  `draft-irtf-cfrg-cpace-21`
- Primary source: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21>
- Commands:
  - `cargo test --test cpace`
  - `cargo test --lib cpace::field::tests`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets`

## Result

Eight integration checks and two focused generated-field checks pass. They
reproduce the official revision-21 generator, role-A share, role-B share,
shared point, and 64-byte ISK exactly. They also reproduce all published
X25519 low-order rejection vectors and the published valid/non-canonical input
vectors.

The local negative checks demonstrate that the core rejects a low-order peer
share and same-side completion, binds PRS, CI, sid, ADa, and ADb, and uses the
same API and message flow for a human-secret byte string and a 16-octet secret.
Ephemeral scalars, generator inputs, shared points, ISKs, and ISK inputs use
zeroizing storage where they cross the public CPace boundary. Debug output
redacts ephemeral scalars and ISKs.

The accepted implementation pins `x25519-dalek` 2.0.1 and `fiat-crypto` 0.3.0.
The small local field wrapper follows the draft's Z=2 Elligator2 formula using
Fiat-Crypto-generated Curve25519 operations. An evaluated
`curve25519-elligator2` 0.1.0-alpha.2 candidate was rejected and removed: its
public mapper cleared the top two input bits and produced `97ef...fe23`, while
revision 21 requires clearing bit 255 only and produces the official
`d04b...a73f` generator.

Prior recogniser, mailbox, limiter, and observability tests remain green. The
aggregate Red Gate now stops at `secure-channel`.

## Scope boundary

This satisfies the implementer-owned `cpace-core` slice and local portions of
`TEST-007` and `TEST-016`. Full wrong-secret invitation consumption in
`TEST-006`, Finished/key-schedule checks, the independent implementation, and
the named human cryptography review remain later gates. This evidence does not
approve production use.

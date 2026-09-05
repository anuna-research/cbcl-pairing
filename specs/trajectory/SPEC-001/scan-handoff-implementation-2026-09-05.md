---
title: Shared confidential handoff implementation evidence
mode: reference
date: 2026-09-05
task: spec-077 handoff
branch: circus/scan-handoff/2
baseline: b703e31ea3d83a74e460fde90a9cf7f33cb6e0d0
generation-model: OpenAI GPT-6 / Codex
review-owner: root
status: local implementation complete; independent acceptance pending
---

# Shared confidential handoff implementation evidence

This record covers the [[SPEC-001-reusable-blind-pairing#REQ-031|confidential handoff]]
codec and allocator convenience API. Its acceptance derives from
[[SPEC-077-selfsame-scan-pairing#CON-001]],
[[SPEC-077-selfsame-scan-pairing#TEST-001]] and
[[SPEC-077-selfsame-scan-pairing#TEST-006]].
The governing consumer spec was read at
`/Users/anuna-01/Code/cbcl-bus/specs/SPEC-077-selfsame-scan-pairing.md`.

The owner explicitly authorized local implementation against the committed amendments.
Root retains the Elephant promise and independently verifies this Circus commit before acceptance.
This attempt changes no Elephant state, deployment, live endpoint, external message, or main branch.
Consumer integration and the consumer's depth acceptance remain outside this codec task.

## Implemented public API

The following types are reexported directly from `cbcl_pairing::credential_v2`:

```rust
impl CredentialV2Handoff {
    pub fn new(
        carrier: CredentialV2Carrier,
        presence: CredentialV2PresenceCode,
    ) -> Result<Self, CredentialV2HandoffError>;

    pub fn carrier(&self) -> &CredentialV2Carrier;
    pub fn encode(&self) -> Result<zeroize::Zeroizing<String>, CredentialV2HandoffError>;
    pub fn into_parts(self) -> (CredentialV2Carrier, CredentialV2PresenceCode);
}

impl std::str::FromStr for CredentialV2Handoff {
    type Err = CredentialV2HandoffError;
    fn from_str(input: &str) -> Result<Self, Self::Err>;
}

impl CredentialV2AllocatorSession {
    pub fn handoff_text(
        &self,
    ) -> Result<Option<zeroize::Zeroizing<String>>, CredentialV2Error>;
}
```

`CredentialV2HandoffError` has exactly `Version`, `Oversize`, `Encoding`,
`Schema`, `Carrier`, and `Commitment`. Each variant is unit-valued.
Its `Display` and `Debug` contain only the category, with no underlying error source.
The handoff itself has no `Display`; normal and alternate `Debug` both produce
`CredentialV2Handoff([REDACTED])`.

`handoff_text` takes no caller carrier. It borrows the retained bootstrap state,
clones that exact public carrier, and copies its still-retained C/T into the typed wrapper.
It returns `None` before allocation, after T consumption, and in terminal or established states.
The shell remains responsible for checkpoint/application commit ordering and clearing its displayed text at expiry.
The method has no clock parameter and does not independently detect elapsed wall time.
Restoration retains the original deadline and refuses at or after expiry.

## Recognition and secret storage

`src/credential_v2/handoff.rs` recognizes `SSPAIR1:` and canonical unpadded
base64url over deterministic CBOR `["selfsame-pairing-handoff/v1", carrier, C, T]`.
It checks text length before allocation or scanning. Decoding uses a zeroizing
2762-byte array, and the outer parser borrows slices without recursive decoding or allocation.
Only minimal definite string headers are accepted inside the exact four-member array.
Full outer recognition precedes the unchanged public carrier decoder.
Canonical re-encoding must equal the entire input.

Bounds are carrier 2695, decoded 2762, suffix 3683, and text 3691 bytes.
The encoder reserves the proven maximum before adding secrets, preventing vector reallocation.
Decoded storage, the encoded suffix buffer, and returned text zeroize on drop.
The owned `CredentialV2PresenceCode` now derives `Zeroize` and `ZeroizeOnDrop`.
Its existing display/parser temporary payload and normalized input also use `Zeroizing`.
A `pub(super)` borrow helper supplies the codec; no new public raw-secret accessor exists.
These storage guarantees follow the zeroize types/derive implementation; no unsafe freed-memory inspection is claimed.

The constructor calls exactly the existing `claim_commitment(M, T)` and compares
the result with `subtle::ConstantTimeEq`. C does not enter the commitment.
Changing C with M/T fixed remains valid; committing to M/C/T is rejected.
Carrier encoding, digest, CPace implementation and inputs, and relay wire sources remain unchanged.
The codec has no profile-verifier, transport, network or persistence callbacks.

Composition uses the existing carrier recognizer, claim commitment, retained bootstrap
presence, and zeroize dependency. The only added dependency is exact `base64ct = 1.8.3`
with `alloc`; that version was already locked. Both Cargo lockfiles add only the
root package's dependency edge. A short direct outer parser supplies the fixed schema
without extending the generic CBOR parser.

## Test evidence and commands

Toolchain: `rustc 1.96.0 (ac68faa20 2026-05-25)` and
`cargo 1.96.0 (30a34c682 2026-05-25)`, aarch64 macOS.
Commands ran from this Circus worktree. Logs reside under
`specs/trajectory/SPEC-001/scan-handoff-evidence/`.

Build commands used `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0`.
Disk exhaustion interrupted an initial build and one mutation link.
Neither interruption counted as behavioral evidence.
Only this attempt's generated target directory was cleaned or moved.
Subsequent builds used `CARGO_TARGET_DIR=/Volumes/ScanHandoffBuild/target` on a temporary 1 GiB RAM disk.
That location is disposable; a verifier can omit it on a filesystem with sufficient space.

| Gate | Exact command after the build environment above | Observed outcome | Log |
|---|---|---|---|
| Behavioral red | `cargo test --test credential_v2_handoff --test credential_v2_handoff_session --no-fail-fast` | Exit 101; codec 0 passed / 7 failed, session 0 passed / 2 failed | `red.log` |
| Initial green | `cargo test --test credential_v2_handoff --test credential_v2_handoff_session --no-fail-fast` | Exit 0; codec 7 passed, session 2 passed | `initial-green.log` |
| Commitment mutation | `cargo test --locked --test credential_v2_handoff commitment_guard` | Exit 101; both constructor and recognizer tests ran and failed by accepting mismatched T | `mutation.log` |
| Restored focused green | `cargo test --locked --test credential_v2_handoff --test credential_v2_handoff_session --test credential_v2_presence --test credential_v2_allocator_session --test credential_v2_bootstrap_checkpoint` | Exit 0; 17 passed, zero failures | `restored-green.log` |
| Library regression | `cargo test --locked --lib --tests` | Exit 0; 147 passed across 28 test binaries, zero failures | `library-regression.log` |
| Bounded fuzz harness | `cargo run --example credential_v2_handoff_fuzz -- 10000` | Exit 0; 70,000 cases, maximum input 4096, no panic | `fuzz.log` |
| Focused lint | `cargo clippy --locked --lib --test credential_v2_handoff --test credential_v2_handoff_session --example credential_v2_handoff_fuzz -- -D warnings` | Exit 0 | `clippy.log` |

The initial stub implemented all requested signatures. `new`, `from_str` and
`encode` returned `Schema`; session export returned `Ok(None)`.
The recorded red gate contains executed assertion failures, including a valid
vector rejected by `new` and retained C/T not exported after checkpoint persistence.
Compilation-only failures from stub documentation and fixture setup were corrected
before capturing that red gate.

For the mutation, the following real production guard was removed:

```rust
if !bool::from(commitment.ct_eq(carrier.claim_commitment())) {
    return Err(CredentialV2HandoffError::Commitment);
}
```

Its temporary replacement was:

```rust
let _ = commitment.ct_eq(carrier.claim_commitment()); // MUTATION: accept mismatched T
```

Both targeted tests then failed at `unwrap_err()` with
`Ok(CredentialV2Handoff([REDACTED]))`. A Python `try/finally` restored the complete
original source regardless of the test exit code. The subsequent focused and full
library green runs used the restored guard. Constructor and parser checks were
split into separate tests so either failure could not prevent exercising the other.

The full regression first identified the existing manifest fingerprint test in
`tests/profiles.rs`. `git show HEAD:Cargo.toml | shasum -a 256` gave the prior
expected digest `ba516fa79716e9567a839f029761f4c8b0ed460592d5a8c3fdb529507be2af8c`.
`shasum -a 256 Cargo.toml` gave
`3d383a7ec90548b601f1e27f5338efb6a7631f5ef196bd8edf34897692ea2ff0`
after adding base64ct. Only that expected manifest hash was updated; all relay source
and schema fingerprint assertions remain unchanged and pass.

## Coverage and reproduction

`tests/credential_v2_handoff.rs` checks deterministic output, canonical recovery,
exact public bytes/digest, both independent secret values and complete Debug redaction.
The seeded domain generator covers application/relay lengths, optional allocator key,
integer-width expiry boundaries, arbitrary u64 expiry, and independent random C/T.
Its 2048 cases include maximal application 2048, relay 272, u64 expiry and expected key.
Equal C/T bytes are also valid: independent generation does not require inequality.

Negative cases exercise wrong prefixes/case/versions, byte limit plus one, whitespace,
padding and pad bits, bad alphabet, truncation at every byte, nonminimal headers,
indefinite arrays, nesting, trailing bytes, extra members, wrong secret lengths,
malformed/noncanonical inner carriers, all 128 one-bit T substitutions and wrong M.
Session tests use a verifier that panics on any application callback.
They check exact export after allocation persistence, restoration just before expiry,
refusal at/after expiry, export removal upon claimant admission before Finished,
restoration after T consumption, relay closure, and terminal protocol failure.

`tests/support/handoff_vectors.py` independently constructs the synthetic small and
maximum vectors using only Python stdlib CBOR construction, SHA-256 and base64url.
The checked-in `vectors/credential-v2-handoff.json` includes carrier bytes/digest,
C, T, decoded wrapper bytes and exact text. These are test values, not live invitations.
Reproduction passed with:

```sh
python3 tests/support/handoff_vectors.py > /tmp/scan-handoff-vectors.json
cmp vectors/credential-v2-handoff.json /tmp/scan-handoff-vectors.json
```

`examples/credential_v2_handoff_fuzz.rs` is the executable bounded fuzz harness.
It exercises arbitrary UTF-8 candidates, arbitrary decoded bytes, seeded text/CBOR
mutations, corrupted T, and arbitrary/nested inner carriers. Every success must
re-encode identically and preserve the original public digest after reconstruction.
The input budget is 4096 bytes and the deterministic iteration budget is explicit.
It is a deterministic fuzz harness, not a coverage-guided libFuzzer or sanitizer run.
The measured output was:

```text
seed=0x07700006cafef00d iterations=10000 max_input=4096 cases=70000
accepted=11160 version=9232 oversize=2696 encoding=2513 schema=13362 carrier=13832 commitment=2280 non_utf8=14925
```

Formatting was checked only for new Rust files, preserving unrelated existing formatting:

```sh
rustfmt --edition 2021 --check src/credential_v2/handoff.rs tests/credential_v2_handoff.rs tests/credential_v2_handoff_session.rs examples/credential_v2_handoff_fuzz.rs
git diff --check
cargo metadata --locked --offline --manifest-path fuzz/Cargo.toml --format-version 1
```

All returned exit 0. The vault check uses `NO_COLOR=true` because this zetl version
rejects the ambient `NO_COLOR=1` spelling; no environment secrets were inspected.
The baseline `NO_COLOR=true zetl -d specs check --dead-links --fail-on error` returned exit 0.
The same final command returns exit 1 with three unresolved cross-vault links to
the consumer spec cited at the start of this record; all other diagnostic arrays are empty.
Those links refer to the existing external file at the absolute path recorded above.
Open: root owns cross-vault index configuration; importing a consumer specification
into this codec-only change is deferred. The links remain visible in the graph.
The actual governing clauses were read directly and implemented/tested as recorded here.

The skill's count audit command was
`/Users/anuna-01/.agents/skills/anuna-dev/tools/usdd-count.sh specs/trajectory/SPEC-001/scan-handoff-implementation-2026-09-05.md`:

```text
artefacts   REQ=1 CON=1 TEST=2 SPEC=2
gate rows   0  (pass=0 fail=0 unverified=0)
wikilinks   4  (anchored=4)
```

Independent semantic review, Circus acceptance and integration remain root's next actions.

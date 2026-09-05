---
title: Bounded pairing-manual implementation evidence
mode: reference
date: 2026-09-05
task: spec-077 pairing-manual
branch: circus/pairing-manual/1
baseline: 1bc4b1d558e577b6eb758dd46e8bf16b125e2c8c
generation-model: OpenAI GPT-6 / Codex; exact model build unavailable
review-owner: root
status: own implementation and execution evidence; independent acceptance pending
---

# Bounded pairing-manual implementation evidence

Root receives this isolated Circus change for independent review, acceptance and merge. The owner authorized this implementation against the reviewed root-owned `plans/IMPL-077-selfsame-scan-pairing.spl`, read from `/Users/anuna-01/Code/cbcl-bus`. This worker changed no Elephant state or sibling worktree and ran no push, deployment or production script. The separately requested public API handoff was published to `/tmp/spec078-pairing-api-handoff.md` as soon as signatures stabilized.

The source contracts are this repository's [[SPEC-001-reusable-blind-pairing]] v0.5.10-draft, [[SPEC-078-selfsame-manual-pairing]] v0.1.1 and [[SPEC-079-selfsame-single-link-consent]] v0.1.1. The latter two were read directly from `/Users/anuna-01/Code/cbcl-bus/specs`. The anuna-dev skill, protocol's implementation, testing and scope instructions, and Circus completion contract governed this attempt. Root's prompt supplies local implementation authority and reserves independent review and all integration/production authority to root.

## Result and boundaries

The shared manual codec implements canonical `SSPAIR-M1:` carrier-plus-T transfer and independent three-word recognition/encoding. It reuses `bip39 = 2.2.2` English list, existing SHA-256 and zeroizing types, the carrier recognizer, and the nonrecursive fixed-string schema parser already used by the full handoff. The bootstrap contains no C or checksum; the tests bind different checksum-valid phrases to identical bootstrap bytes. Complete local recognition checks both raw bounds, the exact phrase language and checksum, canonical wrapper, carrier, commitment, allocator key and exclusive relay expiry.

Allocator input now requires explicit `CredentialV2AllocatorMode::{Full, Manual}`. The bootstrap seals the exact inner v3 domain plus mode octet; every following field retains its prior encoding and order. An old inner v2 tag restores Full, including when C has the manual mapping prefix. The established and claimant formats remain unchanged. An established session reports no bootstrap mode and exports no transfer.

The former session restore constant `[0; 32]` is removed. `CredentialV2AllocatorSession::restore` now takes `expected_mode` and fresh shell-supplied `fresh_cpace_scalar: [u8; 32]` after `now`, before the body verifier. The scalar is held in an optional zeroizing value only for an allocated pre-peer bootstrap and consumed on its first accepted share. Peer-bound restoration discards the supplied fresh value, validates the retained scalar against the exact cached share/Finished, and preserves deterministic replay. The low-level bootstrap API gains explicit mode arguments; its existing `start_cpace` still requires an explicit shell scalar and retains its prior low-level recovery states.

The first peer, consumed T, scalar, cached reply and next generation use the existing persistence gate. No Ack or Put is released until `checkpoint_persisted` acknowledges that generation. A crash before persistence has released no online response. A crash after persistence can replay only the retained peer and cached frame; another share terminates. Local recomputations of retained state do not create another distinct peer-bound attempt. Terminal failure now also drops a session's unconsumed scalar/presence and clears its wrapping key. This preserves sealed external recovery rather than adding a new recovery format.

`CredentialV2TofuState::CeremonyGesture` extends the existing consumer-owned display authority field. The unchanged peer object and claims can render any of the three provenance values only as selected by separately authenticated consumer authority. Ceremony contact is never mapped to `TrustedPair`; existing profile equality and verifier refusal still constrain display. No peer-authentication rule or application wire member changes.

The public manual types are `CredentialV2ManualBootstrap`, `CredentialV2ManualWords` and `CredentialV2ManualError`. `recognise_pair(bootstrap, words, now)` returns the existing `(CredentialV2Carrier, CredentialV2PresenceCode)` types. `Words::from_csprng([u8;4])` supplies mapped C and zeroizing encoded words. `session.manual_transfer_text()` returns an optional pair of zeroizing bootstrap/phrase strings and refuses Full. Existing full and legacy exporters refuse Manual. Export timing, private callbacks, authenticated earlier hub/relay expiry and browser ownership remain shell obligations.

## Requirement attribution and executed evidence

All command logs and the machine-readable gate record are under `evidence/manual-pairing/`.

| Governing property | Executed tests and evidence |
|---|---|
| [[SPEC-078-selfsame-manual-pairing#REQ-001]], [[SPEC-078-selfsame-manual-pairing#TEST-001]], [[SPEC-001-reusable-blind-pairing#TEST-066]] | `tests/credential_v2_manual.rs`: pinned list digest, boundary n values, every checksum branch, indices, exact C, canonical minimum keyed live and maximum carrier/bootstrap vectors; independent real CPace shares, ISK, context, transcript and both Finished values. `vector-reproduction.log` records exact regenerated byte equality. |
| [[SPEC-078-selfsame-manual-pairing#REQ-002]], [[SPEC-078-selfsame-manual-pairing#TEST-002]] | Same codec test file: raw bounds, every truncation, noncanonical base64 pad bits, CBOR nonminimal/indefinite/nested/extra/trailing input, unknown versions, carrier/commitment/key failures, checksum failures, complete ASCII separator and case boundaries, non-ASCII, abbreviations and extra words. `fuzz.log` records bounded recognizer/property execution. |
| [[SPEC-078-selfsame-manual-pairing#REQ-003]], [[SPEC-078-selfsame-manual-pairing#TEST-003]], [[SPEC-001-reusable-blind-pairing#TEST-065]] | `tests/credential_v2_manual_session.rs`: fresh supplied scalars in both modes, persistence before output, wrong valid phrase followed by correct/different share, crash positions around persistence/Ack/Put, repeated exact replay, wrong Finished and no application callbacks. `src/credential_v2/bootstrap/tests.rs` checks retained scalar/cache corruption before recovered output. |
| [[SPEC-078-selfsame-manual-pairing#REQ-005]], [[SPEC-078-selfsame-manual-pairing#REQ-006]], [[SPEC-078-selfsame-manual-pairing#TEST-006]], [[SPEC-001-reusable-blind-pairing#TEST-063]] | Bootstrap tests check exact inner tag and unchanged following fields, encrypted mode mutation, expected-mode mismatch, and every old bootstrap phase restoring Full only. Session tests check mode/export separation, Full C with manual prefix, consumed/terminal exporters and exclusive replay expiry. Existing full/legacy vectors and suites pass unchanged. |
| [[SPEC-078-selfsame-manual-pairing#REQ-007]], [[SPEC-078-selfsame-manual-pairing#TEST-007]], [[SPEC-001-reusable-blind-pairing#TEST-064]] | The existing allocator session's decision/comparison/payload/receipt/recovery fixture runs through Manual admission and real CPace/Finished. Independent context vectors check the sole ceremony ID and exactly thirteen public-context members. The existing library/integration/doc suite exercises unchanged endpoint, admission, receipt, status-recovery, relay and legacy behavior. |
| [[SPEC-079-selfsame-single-link-consent#CON-001]], [[SPEC-001-reusable-blind-pairing#CON-029]], [[SPEC-001-reusable-blind-pairing#TEST-062]] | `tests/credential_v2_display.rs::ceremony_contact_is_truthful_and_cannot_be_supplied_by_peer_claims`: identical peer bytes, each consumer provenance, exact output, and verifier refusal before display. |

No core test claims native identity installation, actual hub signatures, browser Web Locks/IndexedDB fencing, native user presence or served WASM integration. The manual application sequence uses the existing test body verifier; it proves reducer/channel sequencing, not production signature validation. Those consumer-owned branches and [[SPEC-078-selfsame-manual-pairing#TEST-008]] / [[SPEC-079-selfsame-single-link-consent#TEST-011]] remain root's work after the reviewed merge.

## Behavioral red gates and repairs

`tools/run-manual-mutations.py` applies bounded local mutations, captures subprocess output, and restores the original source in `finally`. `mutations/results.json` contains every exact replacement, command, exit code and log. A result counts only when a Rust test executes and reports `test result: FAILED`; missing symbols or compilation failures cannot count.

The final run produced 33 behavioral reds. It removes or corrupts word/bootstrap/C domains, bit shifts, byte order, uniform masking, checksum comparison, phrase/bootstrap bounds, separator language, complete wrapper recognition, commitment, allocator key, expiry equality, authenticated mode encoding, expected mode, old Full restore, all exporter mode checks, pre-peer scalar selection, retained share/Finished checks, the distinct-peer guard, persistence and reentry gates, terminal exports/erasure and display provenance. The `pre-peer-zero-scalar.log` run specifically substitutes the former zero scalar and fails the response-equals-supplied-scalar assertion. The final sweep is `mutation-final.log`; all mutations were restored before `restored-focused-green.log`.

Two fixture defects were corrected without changing protocol code: the independent Python vector initially omitted the inner CPace frame's version integer, and the inner-tag unit fixture initially counted eight outer members instead of the normative nine. `oracle-fixture-correction.log` and `recovery-initial.log` retain those failures. They are fixture corrections, not behavioral red evidence for a production defect. An initial mutation runner stopped because its commitment anchor also matched the checksum check; it was narrowed before execution. That harness failure remains in `mutation-run.log` and is not counted. Initial Clippy feedback identified the two tuple return signatures; narrowly scoped type-complexity allowances preserve the simple public API without another container type.

## Reproduction and measured results

Every Cargo invocation used the existing pinned local git dependency without retargeting, and these environment values:

```sh
export CARGO_TARGET_DIR=/Volumes/anuna-03/codex-spec078-pairing-target
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_INCREMENTAL=0
```

No target was built on the system disk. Existing runtime temporary-path guards were not edited.

| Command | Observed result | Log |
|---|---|---|
| `cargo test --offline --lib --test credential_v2_manual --test credential_v2_manual_session --test credential_v2_allocator_session --test credential_v2_bootstrap_checkpoint --test credential_v2_handoff --test credential_v2_handoff_session --test credential_v2_display` | Exit 0; 45 passed, no failures or ignored tests | `restored-focused-green.log` |
| `cargo test --offline --all-features` | Exit 0; 176 passed, no failures or ignored tests, including doc tests | `library-integration-doc.log` |
| `cargo clippy --offline --all-features --all-targets -- -D warnings` | Exit 0 | `clippy.log` |
| `python3 -B tools/run-manual-mutations.py` | Exit 0; every selected mutation produced an executed behavioral failure | `mutation-final.log`, `mutations/results.json` |
| `cargo run --offline --example credential_v2_manual_fuzz -- 10000` | Exit 0; all closed recognizer outcomes exercised | `fuzz.log` |
| `python3 -B tests/support/manual_vectors.py` compared with checked-in JSON | Exact byte equality | `vector-reproduction.log` |
| New-file `rustfmt --check` and `git diff --check` | Exit 0 | `gates.json` |
| `NO_COLOR=true zetl -d specs --no-cache check --dead-links --fail-on error --json` | Exit 1; existing unresolved SPEC-077 links in the earlier scan handoff evidence | `vault-check.json` |

The vector generator uses Python integer field arithmetic and the existing Python cryptography X25519 primitive, independently of Rust output. Its field-map construction follows [draft-21 Appendix A.5](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21#appendix-A.5) and is checked against that draft's generator example before manual vectors are produced. The checked-in synthetic vectors are not live invitations. Word-list bytes are read from the exact pinned dependency and their LF-terminated SHA-256 is asserted. Vector SHA-256 is `857441abdc181030e9d9432e762002c4a90d432ba9fbd3d07ce4c9e983b5e068`.

The bounded harness uses seed `0x07800002cafef00d`, 10,000 iterations and a maximum input of 4,096 bytes. It combines arbitrary UTF-8/ASCII candidates, seeded wrapper mutations, nested/random carriers, valid generated phrases, accepted normalization and random list-word triples. Successful inputs must re-encode exactly or normalize to the identical mapped C. This is deterministic bounded fuzz/property coverage, not coverage-guided fuzzing, a sanitizer run or measured heap-erasure analysis.

`scope.json` compares the baseline and current bytes of manifests, dependency lock, specifications, CPace constructions, public context, carrier/presence, wire frames/objects, channel/checkpoint/claimant formats, relay sources, dialects and wire schemas. Every listed file is unchanged. Formatting was limited to new files and hunks intersecting this task's changes.

Open — root: independent adversarial review, Circus acceptance/merge, cross-vault link resolution, consumer integration, dependency pin closure and exact served-WASM verification. Root also retains human cryptographic review and production approval. This evidence grants neither cryptographic approval nor production permission.

## Mechanical note inventory

Exact `usdd-count.sh evidence/manual-pairing-2026-09-05.md` output:

```text
artefacts   REQ=6 CON=2 TEST=12 SPEC=4 IMPL=1 
gate rows   0  (pass=0 fail=0 unverified=0)
wikilinks   23  (anchored=20)
```

Descriptive lint exits successfully with three nonblocking long-sentence warnings; its complete output is `evidence/manual-pairing/evidence-lint.json`.

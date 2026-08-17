# Broad mutation sweep — 2026-08-16

This record captures the first full `cargo-mutants` sweep of the library. The
sweep is exploratory tooling and is not a gate; `tools/run-mutations.sh` remains
the required check. Nothing here grants production approval.

## Command and configuration

- `tools/run-mutant-sweep.sh`, `cargo-mutants 27.1.0`, `--jobs 4`.
- Configuration in `.cargo/mutants.toml`: `--all-features --locked`,
  `RUST_TEST_THREADS=1`, `timeout_multiplier = 6.0`,
  `minimum_test_timeout = 300`.
- Excluded: `src/bin/**`, `examples/**`, `fuzz/**`, and `fmt::Debug` /
  `fmt::Display` impls.
- Baseline: 94 tests pass in the unmutated tree.

The sweep ran in two parts after the first attempt was interrupted at 471
verdicts. Part two re-ran the eight incomplete files. Results were merged with
part two authoritative for any file it swept; the union is 1101 unique mutants
with no duplicates.

## Results

| Verdict | Count |
| --- | ---: |
| Caught | 803 |
| Missed (survived) | 118 |
| Timeout | 2 |
| Unviable (did not compile) | 178 |
| **Total** | **1101** |

Viable mutants: 923. **Mutation score: 803/923 = 87.0% killed.**

The two timeouts are genuine non-termination, not measurement artefacts:
`leb128_size` with `>=` flipped to `<`, and `append_leb128` with `==` flipped to
`!=`. Both make the varint loop never terminate. They are correctly classified
as hangs rather than survivors.

An earlier run of this sweep reported 452 timeouts. That run was invalid: an
unrelated `hark daemon` process was consuming 8.3 of 10 cores throughout, so
mutants were killed at the deadline while still running. It is recorded here
only so the discarded numbers are not mistaken for a finding.

## Survivors by file

| File | Survivors |
| --- | ---: |
| `src/cbcl_protocol.rs` | 40 |
| `src/profile.rs` | 34 |
| `src/endpoint.rs` | 27 |
| `src/wire.rs` | 8 |
| `src/cpace.rs` | 5 |
| `src/channel.rs` | 4 |

`src/limiter.rs`, `src/mailbox.rs`, `src/observability.rs`, `src/relay.rs`,
`src/storage.rs`, `src/context.rs`, and `src/cpace/field.rs` had **no
survivors**.

## Survivors by kind

| Kind | Count |
| --- | ---: |
| Boolean operator flip (`\|\|` ↔ `&&`) | 43 |
| Comparison operator flip | 27 |
| `Result` return forced to `Ok(..)` | 26 |
| Other | 12 |
| Arithmetic assignment flip | 3 |
| Collection return emptied | 3 |
| Numeric return forced to a constant | 2 |
| Predicate forced to a constant | 2 |

## Triage

Three patterns account for most of the survivors, and the first is the one that
matters.

### 1. Whole validators can be replaced by `Ok(())` unnoticed

These functions can have their entire body deleted and no test fails:

- `validate_ceremony` → `Ok(())`
- `validate_opener_simple` → `Ok(())`
- `validate_exact_cast` → `Ok(())`
- `EndpointReducer::validate_expected_role_keys` → `Ok(())`
- `EndpointReducer::retry_pending` → `Ok(vec![])`
- `EndpointReducer::retry_pending_finished` → `Ok(vec![])`

A validator that can be neutered without a failing test is only being exercised
on inputs it accepts. The rejection paths are either untested or are reached
through another gate that rejects first, which means the validator is not
independently load-bearing in the suite. These are the strongest candidates for
promotion into curated patches under `mutations/`.

Related, in the same class:

- `<impl CbclSigner for PublicVerifier>::sign` survives returning `vec![]`,
  `vec![0]`, and `vec![1]`.
- `channel_frame_digest` survives returning `Ok([0; 32])` and `Ok([1; 32])`.
- `SecureChannel::transcript_hash` survives returning `[0; 64]` and `[1; 64]`.
- `BootstrapPerformative::is_cpace` survives being forced to `true`.
- `EndpointReducer::admit_bootstrap_control` survives its
  `verdict() != ProtocolVerdict::Violation` match guard being forced to `true`.

The last two are worth attention on their own: a predicate that always answers
`true` and an admission guard that ignores a `Violation` verdict are exactly the
shapes the curated security mutations exist to catch.

### 2. Boolean flips in multi-clause conditions (43)

`||` → `&&` survives in `validate_opener_simple` (6 occurrences),
`PairingDialects::install_sources` (4), `validate_exact_cast`,
`validate_bound_control`, `encode_control`, and across many
`EndpointReducer` methods. Tightening a rejection condition from "any clause"
to "all clauses" changes which inputs are refused, so surviving means the tests
only ever supply inputs where every clause agrees. Each flip marks a rejection
case with no test behind it.

### 3. Comparison boundary flips (27)

`>` → `>=` and `>` → `==` survive in `bounded_ascii_sexpr`, `encode_control`,
`recognise_signed_control`, `build_bound_control`, and
`validate_bound_control`. These are off-by-one boundaries on length and bound
checks. Surviving means no test sits exactly on the boundary — the suite tests
comfortably-inside and comfortably-outside values but not the edge.

`src/cpace.rs` survivors are all inside `leb128_size` / `append_leb128`
(`+=`→`*=`, `+=`→`-=`, `>>=`→`<<=`, `|`→`^`, and the function forced to `1`),
which says the varint encoder is only exercised on values where these
operations coincide — most likely single-byte inputs.

## Recommended next steps

These are proposals, not completed work:

1. Add boundary-case tests for the length and bound checks in
   `cbcl_protocol.rs` and `wire.rs`, which would kill most of the 27 comparison
   survivors.
2. Add rejection-path tests for `validate_opener_simple`, `validate_exact_cast`,
   `validate_ceremony`, and `validate_expected_role_keys`, one per clause.
3. Exercise `leb128_size` / `append_leb128` on multi-byte values.
4. Promote the highest-value survivors — the `Ok(())` validator deletions and
   the `admit_bootstrap_control` guard — into curated patches under
   `mutations/` so they become part of the required gate.

## Follow-up: tests written against these survivors

Nine tests were added in response to the triage above, and every claim below was
re-verified by re-running `cargo-mutants` over the affected file rather than
assumed from the test passing.

| File | Survivors before | Survivors after |
| --- | ---: | ---: |
| `src/cbcl_protocol.rs` | 40 | 25 |
| `src/profile.rs` | 34 | 18 |
| `src/endpoint.rs` | 27 | 27 |

Thirty-one survivors killed. Each new test carries a positive control asserting
that the valid case still succeeds, so a negative case that failed for an
unrelated reason would not be mistaken for coverage.

In `tests/cbcl_protocol.rs`:

- `ceremony_identifier_must_be_exactly_sixty_four_lowercase_hex_digits`
- `control_encoding_accepts_the_maximum_length_and_refuses_one_octet_more`
- `the_role_opener_admits_only_the_exact_inert_hello`
- `the_session_store_counts_every_distinct_admitted_control`
- `each_dialect_source_is_pinned_independently`
- `control_nesting_is_accepted_at_the_maximum_depth_and_refused_one_deeper`

In `tests/profiles.rs`:

- `bounded_claim_text_holds_at_its_exact_limit_and_refuses_the_edges`
- `credential_origins_must_be_canonical_https_authorities`
- `grant_payloads_hold_at_both_ends_of_their_size_bound`
- `synthetic_claims_are_bounded_on_both_fields`

In `tests/endpoint.rs`:

- `a_replayed_channel_frame_is_refused_and_terminates_the_endpoint`

## What the surviving mutants turned out to mean

Verifying rather than assuming changed the conclusion in three places. These are
not test gaps; they are redundant defensive code, and no test can distinguish
them at the public boundary.

- **`validate_exact_cast` is unreachable by difference.** `open_for_ceremony`
  compares `params != exact_opener_params(..)` — an exact equality — at
  `src/cbcl_protocol.rs:484`, before calling `validate_exact_cast` at 489.
  Nothing the cast validator could reject survives to reach it. Its three
  mutants are equivalent.
- **`canonical_https_origin`'s clause checks are subsumed by its own final
  comparison.** The canonical string is rebuilt from host and port alone, so the
  closing `value != canonical` check already rejects every username, password,
  query, fragment, and path deviation that the five `||` clauses screen for.
  Those five mutants are equivalent; the four `Ok(())`-style mutants in the same
  area were killed.
- **The endpoint's replay guards sit behind channel-level replay protection.**
  This was found by writing a test that failed: re-delivering an already-opened
  frame returns `ReducerError::Channel` and terminates the endpoint before
  `apply_intent`, `apply_decision`, or `apply_payload` is reached. The reducer's
  own idempotence checks are therefore unreachable from the frame path, which is
  why `endpoint.rs` retains all 27 survivors. The existing
  `test_022_decision_is_atomic_replay_idempotent_and_conflict_terminal`
  exercises idempotence through the local `decide()` API, not the receive path.

  The test written for this kills no mutant. It was kept because it pins real
  and previously untested behaviour: a replayed frame is treated as tampering.

Reaching the remaining `endpoint.rs` survivors would need the reducer's
`retry_pending` path driven directly, or the guards recognised as redundant and
removed. Either is a design decision, not a test to add.

## Reproduction

```sh
tools/run-mutant-sweep.sh
```

Full verdict lists are in `mutants.out/`, which Git ignores.

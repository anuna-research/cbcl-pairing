#!/bin/sh
set -eu

repository=$(git rev-parse --show-toplevel)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/cbcl-pairing-mutations.XXXXXX")
target="$scratch/target"
trap 'rm -rf "$scratch"' EXIT HUP INT TERM

run_mutant() {
    name=$1
    patch_file=$2
    test_target=$3
    test_name=$4
    case_dir="$scratch/$name"
    log="$scratch/$name.log"
    mkdir -p "$case_dir"
    git -C "$repository" archive --format=tar HEAD | tar -x -C "$case_dir"
    patch --silent -d "$case_dir" -p1 <"$repository/$patch_file"

    if ! CARGO_TARGET_DIR="$target" cargo test --locked --no-run \
        --manifest-path "$case_dir/Cargo.toml" --test "$test_target" >"$log" 2>&1
    then
        echo "INVALID $name (did not compile)"
        sed -n '1,160p' "$log"
        exit 1
    fi

    if CARGO_TARGET_DIR="$target" cargo test --locked \
        --manifest-path "$case_dir/Cargo.toml" --test "$test_target" \
        "$test_name" -- --exact >"$log" 2>&1
    then
        echo "SURVIVED $name"
        sed -n '1,160p' "$log"
        exit 1
    fi
    echo "KILLED $name by $test_target::$test_name"
}

run_mutant store-intent-metadata \
    mutations/01-store-intent-metadata.patch \
    assurance_properties intent_state_retains_no_display_metadata
run_mutant admit-third-membership \
    mutations/02-admit-third-membership.patch \
    mailbox test_003_third_distinct_claim_crowds_and_allocates_no_membership
run_mutant accept-sequence-gap \
    mutations/03-accept-sequence-gap.patch \
    mailbox test_004_sequence_retries_are_idempotent_and_conflicts_are_terminal
run_mutant skip-finished-verification \
    mutations/04-skip-finished-verification.patch \
    channel each_corrupt_finished_value_blocks_channel_activation
run_mutant reuse-aead-nonce \
    mutations/05-reuse-aead-nonce.patch \
    channel both_directions_roundtrip_with_independent_contiguous_counters
run_mutant authorization-is-approval \
    mutations/06-authorization-is-approval.patch \
    endpoint test_019_authorization_cannot_bypass_pairing_gates
run_mutant emit-grant-after-decline \
    mutations/07-emit-grant-after-decline.patch \
    endpoint test_009_decline_erases_both_endpoints_and_releases_no_payload

echo "MUTATION GATE OK: 7/7 killed"

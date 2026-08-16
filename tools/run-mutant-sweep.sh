#!/bin/sh
set -eu

# Broad mutation sweep over the library, driven by cargo-mutants.
#
# This is exploratory tooling, not a gate. `tools/run-mutations.sh` remains the
# required check: it applies the curated security mutations in `mutations/` and
# fails if any survives. This script enumerates every mutant cargo-mutants can
# construct and reports the ones no test kills, so that genuine gaps can be
# promoted into curated patches.
#
# Usage:
#   tools/run-mutant-sweep.sh                 sweep the whole library
#   tools/run-mutant-sweep.sh -f src/wire.rs  sweep one file
#   tools/run-mutant-sweep.sh --in-diff x.diff  sweep only changed lines
#
# Any additional arguments are forwarded to cargo-mutants verbatim.

repository=$(git rev-parse --show-toplevel)
cd "$repository"

if ! command -v cargo-mutants >/dev/null 2>&1; then
    echo "cargo-mutants is not installed." >&2
    echo "Install it with: cargo install cargo-mutants --locked" >&2
    exit 1
fi

# Confirm the unmutated tree is green before spending time on mutants.
# cargo-mutants performs its own baseline run, but failing here gives a far
# clearer message than a baseline failure buried in sweep output.
#
# Retry once. The relay suites block on sockets, so on a loaded machine one of
# them can lose a race and fail spuriously; aborting an hours-long sweep on a
# single flake is worse than paying for a second few-second run. Two failures
# in a row are treated as a genuinely red tree.
if ! cargo test --locked --all-features --quiet >/dev/null 2>&1; then
    echo "Unmutated suite failed once; retrying in case of a load-induced flake." >&2
    if ! cargo test --locked --all-features --quiet >&2; then
        echo >&2
        echo "The unmutated test suite does not pass; fix it before sweeping." >&2
        exit 1
    fi
    echo "Retry passed; continuing." >&2
fi

# A sweep needs several cores for a sustained period. If the machine is already
# saturated, mutants get killed at the timeout and are reported as hangs, which
# looks like a finding but is an artefact. Warn rather than refuse: the caller
# may knowingly accept a slow run.
if [ -r /proc/loadavg ]; then
    load=$(cut -d' ' -f1 /proc/loadavg)
    cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
else
    load=$(uptime | sed 's/.*averages*: *//' | cut -d' ' -f1 | tr -d ',')
    cores=$(sysctl -n hw.ncpu 2>/dev/null || echo 1)
fi
if [ "${load%%.*}" -ge "$cores" ] 2>/dev/null; then
    echo "Warning: load is ${load} on ${cores} cores before the sweep starts." >&2
    echo "Expect spurious timeouts; quiesce the machine for trustworthy results." >&2
fi

# Default the worker count when the caller does not choose one. Each worker runs
# the suite single-threaded (see `.cargo/mutants.toml`), so workers map roughly
# onto cores; leaving several free keeps the relay suites, which spawn their own
# processes, from being starved into spurious timeouts.
case " $* " in
    *" --jobs "* | *" -j "*) ;;
    *) set -- --jobs 4 "$@" ;;
esac

# One test thread per worker, so a worker occupies roughly one core. See the
# note in `.cargo/mutants.toml` for why this is an environment variable.
RUST_TEST_THREADS=1
export RUST_TEST_THREADS

# `set -e` would abort on a nonzero exit before the summary below prints, and
# a nonzero exit is the normal outcome when survivors exist.
status=0
cargo mutants "$@" || status=$?

echo
echo "Sweep artefacts are in mutants.out/:"
echo "  caught.txt     mutants a test killed"
echo "  missed.txt     survivors — no test noticed the change"
echo "  timeout.txt    mutants that hung; treat as inconclusive"
echo "  unviable.txt   mutants that did not compile; expected, not a gap"

exit "$status"

#!/bin/sh
set -eu

cargo +nightly fuzz run wire_recognition -- \
    -runs=10000 -max_len=1024 -timeout=5
cargo +nightly fuzz run mailbox_transitions -- \
    -runs=5000 -max_len=768 -timeout=5
cargo +nightly fuzz run channel_receiver -- \
    -runs=1000 -max_len=512 -timeout=5

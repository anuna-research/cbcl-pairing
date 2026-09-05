# Known relay acknowledgement recovery repair

The actual browser process-death diagnostic restored the exact Manual peer-bound
checkpoint and emitted the original cached Put twice: once after relay Welcome
and once after the relay redelivered the original claimant share. The relay
legitimately acknowledged both stored Puts. The first acknowledgement advanced
ShareSent to FinishedSent; the identical second input terminated the allocator
with Counter. The diagnostic is development evidence, not a passing integration
receipt. Its exact public Acknowledged0 input hash was
`57ae1b908e36bdcf6792916193617bc091324390a918d4b9d36c213c62a0377f`.

This repair implements ordinary idempotent recovery under
[[SPEC-001-reusable-blind-pairing#REQ-031]],
[[SPEC-001-reusable-blind-pairing#CON-030]], and
[[SPEC-001-reusable-blind-pairing#TEST-065]]. It adds one internal predicate over
the existing retained relay sequence and pending-ack projection. A sequence
strictly below the latest queued sequence was already acknowledged because the
unchanged queue operation cannot enqueue a successor while an acknowledgement
is pending. The latest queued sequence is already applied only when the pending
flag is clear. The predicate therefore recognizes known history; it does not
accept an unissued or currently pending sequence as a duplicate.

Allocator and claimant entry points return no effects for that known history.
Current pending acknowledgements retain their existing reducer and checkpoint
path. Unknown/future acknowledgements retain Counter while a frame is pending,
or the existing Phase refusal when there is no frame pending. The closed wire
grammar still rejects out-of-range sequences before either path.

Persistence gates precede duplicate recognition. The allocator retains its
exclusive relay-expiry check, including established state. Ordinary claimant
input retains its expiry check, and durable FinalApproved input retains its
pre-payload expiry guard. Durable PayloadSent retains its existing null expiry;
a duplicate there returns no effects rather than manufacturing another sealed
checkpoint. No new generation or checkpoint nonce is consumed. No wire, ABI,
checkpoint schema, signature, CPace, Finished, relay behavior or source pin is
changed.

The original-source Rust regression reproduced Counter on the second Ack after
an actual restore, Welcome, and peer replay. The repaired test covers Full and
Manual, unchanged cached bytes, the pending checkpoint gate, unknown future
sequences, expiry, and reuse of an ignored nonce at the next genuine checkpoint.
The existing complete application and claimant flows also exercise duplicate
acknowledgements, including durable post-payload recovery without a checkpoint.

Rust 1.85 offline/locked all-features tests passed: 182 tests, including nine
doctests, with zero failures or ignored tests. All-target/all-feature Clippy with
warnings denied and Rust 1.85 formatting checks passed. These aggregate counts
are parsed from the recorded tool output in verification.json.

Four isolated behavioral mutants were killed: rejecting known older
acknowledgements, accepting future acknowledgements, allowing the exact expiry
boundary, and creating a durable checkpoint for a duplicate. Each compiled and
failed the intended test assertion. mutations.json records the exact edits,
mutated-source hashes, commands, and original/stored log hashes. The disposable
worktree did not modify the candidate source under independent review.

Logs remove only line-end whitespace and trailing blank lines. Original raw
hashes are preserved. The earlier test-authoring mistakes (a sequence outside
the closed grammar and expecting Counter at the idle Phase boundary) were
corrected in tests; the production repair was unchanged.

Root and the independent reviewer own acceptance and the exact rebuilt native,
served-WASM and relay crash-recovery run. These component checks do not claim
the complete [[SPEC-078-selfsame-manual-pairing#TEST-008]] or
[[SPEC-079-selfsame-single-link-consent#TEST-011]] depth suite has passed on the
new source closure.

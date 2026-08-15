# CBCL protocol adapter Green Gate — 2026-08-16

Focused command:

```text
cargo test --test cbcl_protocol
```

Result: 10 passed, 0 failed, 0 ignored.

Whole-tree command before closing the component status:

```text
cargo test --all-targets
```

Result: every implemented component test passed. The aggregate Red Gate then
stopped at `cbcl-protocol`, as expected before its status switch. After the
switch, the same command passed every CBCL protocol test and stopped at the
next real component, `endpoint-reducer`.

Static command:

```text
cargo clippy --all-targets --all-features -- -D warnings
```

Result: passed with no warning.

Implemented boundary:

- exact raw-source and canonical-hash installation of both normative dialects;
- cbcl-rs endpoint projection, R5 causality, R6 cast verification, and monotone
  `ThreadedMessageStore` admission;
- 32-octet ephemeral Ed25519 keys, canonical key identifiers, strict signature
  verification through CBCL's explicit v1/full R4 discipline, and zeroizing
  private-key storage;
- bounded canonical textual CBCL controls, deterministic full-message content
  addresses, strict lowercase encodings, and exact adjacent-body binding;
- role-free bootstrap fan-in with `Unknown` producing no store effect;
- one exact transcript-key-bound, canonical-session-hash-pinned inert role root;
- exact session sender/recipient/predecessor checks and independent sibling
  decision verdicts; and
- exact replay idempotence.

Integration finding: cbcl-rs root typing maps the genuine stored opener hash to
the dialect's `begin` edge, but the generic monitor also accepts a literal raw
`begin` for that first act. The pairing adapter therefore requires
`pairing-intent` to cite the actual opener content address before calling the
generic role monitor. This is an adapter invariant from SPEC-072, not a copied
choreography graph.

The pinned `cbcl-parser` surface also does not accept `:` inside symbols, while
the R6 opener grammar requires the unquoted `sha256:<hex64>` pin and the core
S-expression reader used by cbcl-rs's own R6 tests does accept it. Controls use
that core reader behind a 2,048-octet ASCII and depth-8 preflight, followed by
typed `Message` roundtrip equality and exact schema checks. Dialect source
installation continues to use `cbcl-parser`.

This is non-production conformance evidence. Independent cryptographic and
adversarial reviews remain release gates.

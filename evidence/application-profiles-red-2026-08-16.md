# Application profiles Red Gate — 2026-08-16

Command:

```text
cargo test --test profiles
```

Result: 0 passed, 1 failed.

The public endpoint-local profile trait and the fixed agent, credential, and
synthetic descriptors compile. The test executes the real recogniser entry
point for each profile and fails because it returns the explicit
`ProfileError::NotImplemented` sentinel. The relay, mailbox, limiter, reaper,
and shared wire grammar are unchanged.

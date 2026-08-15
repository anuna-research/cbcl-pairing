# Application tutorial

This tutorial describes the intended application experience and the current
library composition. It is for local conformance integration only; the
production gates in `SECURITY.md` are still open.

## 1. Choose a profile, not a new protocol

Use the agent profile when the approved payload creates an agent grant, and the
credential profile when it transfers the specified account credential. A new
project normally implements `ApplicationProfile` and `GrantVerifier`; it does
not fork the mailbox, CPace suite, channel, or CBCL dialects.

The application profile owns what the user sees and what a grant means. The
relay never receives the profile identifier as a protocol field and never
loads profile code.

## 2. Create the out-of-band carrier

The allocator first obtains a mailbox from its selected operator, generates a
fresh invitation secret, and constructs `wire::Invitation` with:

- the fixed suite `CPACE25519-SHA512-D21`;
- its profile application ID;
- the canonical relay origin;
- a direct mailbox ID or numeric nameplate;
- the fresh secret;
- optional expected allocator/claimant ceremony-key digests.

Call `encode_invitation` and transfer those exact bytes by QR/deep link, local
device handoff, or a pinned word-list carrier. Do not put the invitation in
logs, analytics, crash reports, URLs with third-party referrers, or clipboard
history without an explicit product decision.

The built-in agent profile uses two generated word indices, encoded as exactly
four bytes:

```rust
use cbcl_pairing::profile::AgentWordPair;

// `random` is three fresh octets from the application's OS CSPRNG.
# let random = [0x12, 0x34, 0x56];
let carrier = AgentWordPair::from_csprng_octets(random);
let words = carrier.words();
let prs = carrier.secret();
assert_eq!(words.len(), 2);
assert_eq!(prs.len(), 4);
# Ok::<(), cbcl_pairing::profile::ProfileError>(())
```

That is 22 bits of generated choice. It is an online-guess-limited one-time
secret, not a human password. The credential carrier uses 16–64 random octets.

## 3. Recognise and consume before guessing

The claimant recognises the invitation with `decode_invitation`; both apps ask
the selected profile to recognise it. The shell creates and durably persists an
`InvitationRecord` from the exact invitation bytes.

Before either endpoint processes the first peer CPace frame, atomically call
`InvitationRecord::bind` with the resolved mailbox, exact peer frame, and public
transcript context. Persist the returned state before continuing. Only an exact
resume can use a `Bound` record; a different attempt makes it `Spent`.

This small durable record is why endpoint projection does not eliminate every
state variable: CBCL owns legal message history, while the record prevents an
online attacker from gaining repeated guesses after a crash.

## 4. Establish the channel

Each shell supplies a fresh 32-octet CPace scalar and calls
`cpace::start_pairing`. The library derives the canonical `CI`, mailbox `sid`,
and role/key associated data. Encode the returned `CpaceMessage`, sign the
corresponding bootstrap control, and send its `ChannelFrame::Cpace` through the
mailbox.

After both CPace controls are valid, `cpace::finish` produces the shared
intermediate key. Create `PendingChannel` with `PendingChannel::new_pairing`,
that key, the invitation, resolved mailbox, and the two exact CPace frames. The
constructor owns the deterministic public-context encoding. The endpoint
reducer emits/accepts the role-bound Finished frames.

No intent, approval UI, payload, or grant is legal until both Finished values
verify and the R6 session cast opens. A CBCL `Unknown` verdict is retained for
retry but has no cryptographic or user-visible effect.

The complete executable composition, including signed controls and fixed test
randomness, is in `tests/endpoint.rs`.

## 5. Show the intent and ask once

The allocator constructs one `PairingIntent` from profile-recognised claims and
calls `EndpointReducer::send_intent`. On the claimant, pass the received sealed
frame to `EndpointReducer::receive_frame`.

Only render the resulting `EndpointEffect::DisplayIntent`. The reducer has
already authenticated the channel, admitted the projected CBCL control,
recognised the complete profile-specific claims, and retained only their digest
and binding. Suggested UI:

```text
Pair an agent?

Agent: build-runner-7
Authority: Can receive project dispatches for “Atlas”
Peer key: 7B3A … C901

[Decline]                         [Approve]
```

The authority summary must say what changes, not merely “Continue?”. The app
must not show an approval affordance before the `DisplayIntent` effect.

## 6. Apply the decision and grant

The claimant calls `decide(Decision::Approve)` or
`decide(Decision::Decline)`.

- Decline emits a protected decision frame and `CloseMailbox`, erases secret
  state, and can never release a grant.
- Approval permits the allocator to call `send_payload` once for the exact
  accepted intent digest.

The claimant's `receive_frame` passes an approved payload to the profile and
its application-authoritative verifier exactly once. Only
`EndpointEffect::DeliverGrant` authorises the shell to mutate application state.
Then close the mailbox and erase carrier material.

## 7. Transport effects without teaching it the app

Encode each `EndpointEffect::SendFrame` with `encode_channel_frame`, place the
bytes in `ClientMessage::Put`, and acknowledge received `ServerMessage::Frame`
sequences. On reconnect, use `ClientMessage::Open` with the mailbox ID and
membership token. The relay queues at most 16 frames per membership and expires
the whole attempt within at most 600 seconds.

The same endpoint code can instead send channel-frame bytes over an existing
direct duplex connection. Only the adapter changes.

## 8. Integration checklist

- Persist invitation consumption before the first online guess.
- Use CSPRNG output; never copy test constants from examples or fixtures.
- Never build CPace context fields in application code.
- Feed only canonical recognised bytes into the protocol monitors.
- Execute only emitted `EndpointEffect` values.
- Treat terminal errors as terminal and burn the invitation.
- Feed relay closure/expiry to `EndpointReducer::relay_closed`; if this happens
  before reducer construction, call `InvitationRecord::consume` and persist it.
- Keep relay, endpoint, and profile logs free of invitations, locators, tokens,
  identities, intent text, transcript digests, and payload bytes.
- Keep production allocation off until every Tier-1 gate is recorded.

# Security model and production gates

`cbcl-pairing` is security-sensitive experimental code. Passing its local tests
does not approve production use.

## Security claims in scope

Given a fresh one-time secret, honest endpoint software, correctly generated
randomness, and the exact pinned protocol assets, the design aims to provide:

- an authenticated encrypted channel between the two peers;
- online-guess resistance bounded by invitation consumption, expiry, and relay
  limiting;
- explicit key confirmation before application traffic;
- exact role, application, relay, mailbox, invitation, transcript, and optional
  ceremony-key binding;
- replay/gap/wrong-direction rejection with terminal receive state;
- one explicit intent-bound approval before one profile-authorised grant;
- bounded, application-unaware relay storage and privacy-safe observability.

These are design and conformance claims, not a formal security proof.

## What the relay learns

The relay does not receive the invitation secret and does not parse opaque
channel bodies as CPace, Finished, intent, decision, payload, identity, or
credential data. It sees:

- network addresses (or the terminating proxy's address);
- connection, timing, mailbox/nameplate, frame-count, frame-size, and expiry
  metadata;
- membership tokens while presented on the wire, though only hashes are kept
  in mailbox state.

TLS hides transport data from network observers, not from the relay operator.
Traffic analysis, operator compromise, denial of service, intentional crowding,
and invitation consumption remain possible.

## Endpoint trust boundary

The application shell must treat every inbound byte as untrusted until the
matching recogniser accepts it. CBCL verdicts gate protocol admission, Finished
gates cryptographic activation, the application profile gates display and
payload structure, user consent gates release, and `GrantVerifier` gates the
application's own authority policy.

No authorisation primitive—including ABE, IBE, broadcast encryption, an
attribute proof, or a pre-authorised synthetic verifier—may substitute for
CPace, Finished, intent recognition, or explicit approval.

The endpoint reducer retains state that cannot safely live only in a projected
message history: durable invitation consumption, live/terminal cryptographic
material, decision uniqueness, nonce counters, and effect-delivery guards. It
does not duplicate the legal predecessor graph owned by the CBCL dialects.

## Secret and entropy requirements

- All mailbox IDs, membership tokens, invitation secrets, CPace scalars,
  ceremony signing keys, and intent nonces must come from an OS-backed CSPRNG.
- The agent two-word carrier is two independent indices in a pinned 2048-word
  list: 22 bits. It depends on one-time use, short expiry, and online limiting.
- The credential carrier is 16–64 random octets: 128–512 bits.
- Human-chosen words, truncated identifiers, deterministic test scalars, reused
  invitations, and application passwords are not acceptable substitutes.
- A direct invitation binds its exact mailbox. CPace context binds the suite,
  application, relay origin, resolved mailbox, ordered sides, and expected key
  digests.
- The secure-channel public context independently binds the suite, application,
  relay origin, resolved mailbox, and both optional expected key digests.

The exact CPace construction is revision 21 of an Internet-Draft. A later draft
or RFC does not silently update this implementation.

## Erasure and persistence

Secret-bearing Rust values use zeroizing storage where implemented, and
terminal reducer paths drop cryptographic components. The application still
owns copies created in UI, carrier transfer, network buffers, persistence,
telemetry, crash dumps, backups, and foreign-language bindings. Audit those
copies explicitly.

Persist only the secret-free `InvitationRecord` for crash-resume consumption.
The included relay store persists only blind mailbox-domain state; custom stores
must preserve that boundary. Every adapter must delete acknowledged and
terminal bodies immediately, remove interrupted temporary records, and delete
all remaining state at original expiry.

## Mandatory open gates

Production stays disabled until all of the following have named evidence and
owner disposition:

1. a fresh-context adversarial review of the complete specification and code;
2. TEST-016 by a human cryptography reviewer, including CPace draft-21 inputs,
   official and independent vectors, Finished, key separation, and AEAD nonces;
3. TEST-017 by an integration reviewer against two independently operated relay
   deployments and both real profiles;
4. TEST-018 using an independently written endpoint implementation;
5. the applicable human decisions for each production application profile,
   especially credential transfer and proximity policy;
6. all required red/mutation gates and the final Tier-1 assurance audit.

The local evidence directory can support those reviews but cannot self-attest
them. Do not treat `--enable-conformance-allocation`, a green CI run, a release
build, or a downstream application dependency as production approval.

## Reporting

Report suspected vulnerabilities privately to the repository maintainers with
the affected commit, protocol phase, exact input, observed result, and whether
secret or grant material was exposed. Avoid including live invitation secrets,
membership tokens, credentials, or user identities in the report unless a
secure disclosure channel has been agreed.

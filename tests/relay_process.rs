//! Full local two-process portion of SPEC-072 TEST-017.

#![cfg(feature = "relay")]

use cbcl_core::message::CausedBy;
use cbcl_pairing::{
    cbcl_protocol::{
        build_bootstrap_control, BootstrapMonitor, BootstrapPerformative, CeremonySigningKey,
    },
    channel::PendingChannel,
    context::PairingContext,
    cpace,
    endpoint::{
        EndpointEffect, EndpointReducer, InvitationRecord, InvitationStatus, TerminalReason,
    },
    profile::{
        encode_agent_word_indices, AgentGrant, AgentIntentClaims, AgentProfile, ApplicationProfile,
        AuthorisedGrant, CredentialGrant, CredentialIntentClaims, CredentialProfile, DisplayIntent,
        GrantVerifier, ProfileError, RecognisedPayload, AGENT_ACTION, AGENT_APPLICATION,
        AGENT_PAYLOAD, CREDENTIAL_ACTION, CREDENTIAL_APPLICATION, CREDENTIAL_PAYLOAD,
    },
    wire::{
        decode_channel_frame, decode_server_message, encode_channel_frame, encode_client_message,
        encode_cpace_message, encode_invitation, ApplicationPayload, ChannelFrame, ClientMessage,
        Decision, Invitation, Locator, PairingIntent, ServerMessage, Side,
    },
};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

struct RelayProcess {
    child: Child,
    address: String,
    key_file: PathBuf,
}

impl RelayProcess {
    fn start(index: u8) -> Self {
        let key_file = std::env::temp_dir().join(format!(
            "cbcl-pairing-relay-test-{}-{index}.key",
            std::process::id()
        ));
        fs::write(&key_file, [index; 32]).expect("operator key fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600))
                .expect("operator key permissions");
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_cbcl-pairing-relay"))
            .args([
                "--listen",
                "127.0.0.1:0",
                "--operator-key-file",
                key_file.to_str().expect("key path"),
                "--enable-conformance-allocation",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn relay");
        let stdout = child.stdout.take().expect("relay stdout");
        let mut stdout = BufReader::new(stdout);
        let mut line = String::new();
        stdout.read_line(&mut line).expect("listen line");
        let address = line
            .strip_prefix("LISTEN ")
            .expect("listen prefix")
            .trim()
            .to_owned();
        Self {
            child,
            address,
            key_file,
        }
    }

    fn stop(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            pipe.read_to_string(&mut stderr).expect("relay stderr");
        }
        let _ = fs::remove_file(&self.key_file);
        stderr
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.key_file);
    }
}

struct Client {
    stream: TcpStream,
}

impl Client {
    fn connect(address: &str) -> Self {
        let stream = TcpStream::connect(address).expect("connect relay");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("write timeout");
        Self { stream }
    }

    fn send(&mut self, message: &ClientMessage) {
        let bytes = encode_client_message(message).expect("client encoding");
        self.stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .expect("message length");
        self.stream.write_all(&bytes).expect("message bytes");
        self.stream.flush().expect("message flush");
    }

    fn receive(&mut self) -> ServerMessage {
        let mut length = [0_u8; 4];
        self.stream.read_exact(&mut length).expect("reply length");
        let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
        self.stream.read_exact(&mut bytes).expect("reply bytes");
        decode_server_message(&bytes).expect("server recognition")
    }

    fn roundtrip(&mut self, message: &ClientMessage) -> ServerMessage {
        self.send(message);
        self.receive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProfileKind {
    Agent,
    Credential,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProfileResult {
    kind: ProfileKind,
    display: DisplayIntent,
    grant: AuthorisedGrant,
    allocator_invitation: InvitationStatus,
    claimant_invitation: InvitationStatus,
    claimant_verifier_calls: usize,
    claimant_deliveries: usize,
    terminal: Option<TerminalReason>,
}

#[derive(Debug)]
struct RecordingVerifier {
    calls: Arc<AtomicUsize>,
}

impl GrantVerifier for RecordingVerifier {
    fn verify(&mut self, _payload: &RecognisedPayload) -> Result<(), ProfileError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn profile(
    kind: ProfileKind,
) -> (
    Box<dyn ApplicationProfile>,
    Box<dyn ApplicationProfile>,
    Arc<AtomicUsize>,
) {
    let allocator_calls = Arc::new(AtomicUsize::new(0));
    let claimant_calls = Arc::new(AtomicUsize::new(0));
    let make_verifier = |calls: &Arc<AtomicUsize>| -> Box<dyn GrantVerifier> {
        Box::new(RecordingVerifier {
            calls: Arc::clone(calls),
        })
    };
    let allocator: Box<dyn ApplicationProfile> = match kind {
        ProfileKind::Agent => Box::new(AgentProfile::new(make_verifier(&allocator_calls))),
        ProfileKind::Credential => {
            Box::new(CredentialProfile::new(make_verifier(&allocator_calls)))
        }
    };
    let claimant: Box<dyn ApplicationProfile> = match kind {
        ProfileKind::Agent => Box::new(AgentProfile::new(make_verifier(&claimant_calls))),
        ProfileKind::Credential => Box::new(CredentialProfile::new(make_verifier(&claimant_calls))),
    };
    (allocator, claimant, claimant_calls)
}

struct ProfileInputs {
    invitation: Invitation,
    intent: PairingIntent,
    payload_type: &'static str,
    payload_body: Vec<u8>,
}

fn profile_inputs(
    kind: ProfileKind,
    mailbox_id: [u8; 32],
    nameplate: Option<u32>,
) -> ProfileInputs {
    match kind {
        ProfileKind::Agent => {
            let claims = AgentIntentClaims {
                channel: "atlas/stable".into(),
                claimed_principal: "alice@example.test".into(),
                agent_handle: "build-runner-7".into(),
                requested_grant: "project-dispatch".into(),
            };
            ProfileInputs {
                invitation: Invitation {
                    application: AGENT_APPLICATION.into(),
                    relay_origin: "https://relay.example".into(),
                    locator: Locator::Nameplate(nameplate.expect("agent nameplate")),
                    secret: encode_agent_word_indices(17, 1_503)
                        .expect("agent word indices")
                        .to_vec(),
                    expected_allocator_key: None,
                    expected_claimant_key: None,
                },
                intent: PairingIntent {
                    application: AGENT_APPLICATION.into(),
                    action: AGENT_ACTION.into(),
                    allocator_claim: claims.clone().encode().expect("agent claims").0,
                    claimant_claim: claims.clone().encode().expect("agent claims").1,
                    authority_summary: "Receive Atlas project dispatches".into(),
                    intent_nonce: [0xa7; 32],
                },
                payload_type: AGENT_PAYLOAD,
                payload_body: AgentGrant {
                    claimed_principal: claims.claimed_principal,
                    agent_handle: claims.agent_handle,
                    requested_grant: claims.requested_grant,
                    grant: b"signed SPEC-061 project grant".to_vec(),
                }
                .encode()
                .expect("agent grant"),
            }
        }
        ProfileKind::Credential => {
            let claims = CredentialIntentClaims {
                application_id: "com.example.wallet".into(),
                origin: "https://wallet.example".into(),
                scope: "account:read".into(),
                recipient: "new phone".into(),
            };
            ProfileInputs {
                invitation: Invitation {
                    application: CREDENTIAL_APPLICATION.into(),
                    relay_origin: "https://relay.example".into(),
                    locator: Locator::Direct(mailbox_id),
                    secret: vec![0xc7; 16],
                    expected_allocator_key: None,
                    expected_claimant_key: None,
                },
                intent: PairingIntent {
                    application: CREDENTIAL_APPLICATION.into(),
                    action: CREDENTIAL_ACTION.into(),
                    allocator_claim: claims.clone().encode().expect("credential claims").0,
                    claimant_claim: claims.clone().encode().expect("credential claims").1,
                    authority_summary: "Transfer account:read credential to new phone".into(),
                    intent_nonce: [0xc7; 32],
                },
                payload_type: CREDENTIAL_PAYLOAD,
                payload_body: CredentialGrant {
                    application_id: claims.application_id,
                    origin: claims.origin,
                    scope: claims.scope,
                    recipient: claims.recipient,
                    credential: b"account-scoped credential".to_vec(),
                }
                .encode()
                .expect("credential grant"),
            }
        }
    }
}

struct Endpoints {
    allocator: EndpointReducer,
    claimant: EndpointReducer,
    allocator_cpace: ChannelFrame,
    claimant_cpace: ChannelFrame,
}

fn endpoints(
    invitation: &Invitation,
    mailbox_id: [u8; 32],
    allocator_profile: Box<dyn ApplicationProfile>,
    claimant_profile: Box<dyn ApplicationProfile>,
) -> Endpoints {
    let invitation_bytes = encode_invitation(invitation).expect("invitation");
    let ceremony = cbcl_pairing::cbcl_protocol::ceremony_id(&invitation_bytes);
    let allocator_key = CeremonySigningKey::from_secret([0x11; 32]).expect("allocator key");
    let claimant_key = CeremonySigningKey::from_secret([0x22; 32]).expect("claimant key");
    let (allocator_cpace_state, allocator_message) =
        cpace::start_pairing(Side::Allocator, invitation, mailbox_id, [0x41; 32])
            .expect("allocator CPace");
    let (claimant_cpace_state, claimant_message) =
        cpace::start_pairing(Side::Claimant, invitation, mailbox_id, [0x42; 32])
            .expect("claimant CPace");
    let allocator_isk =
        cpace::finish(allocator_cpace_state, &claimant_message).expect("allocator ISK");
    let claimant_isk =
        cpace::finish(claimant_cpace_state, &allocator_message).expect("claimant ISK");
    let allocator_body = encode_cpace_message(&allocator_message).expect("allocator message");
    let claimant_body = encode_cpace_message(&claimant_message).expect("claimant message");
    let allocator_control = build_bootstrap_control(
        &allocator_key,
        BootstrapPerformative::CpaceA,
        &ceremony,
        &allocator_body,
        CausedBy::Begin,
    )
    .expect("allocator control");
    let claimant_control = build_bootstrap_control(
        &claimant_key,
        BootstrapPerformative::CpaceB,
        &ceremony,
        &claimant_body,
        CausedBy::Begin,
    )
    .expect("claimant control");
    let allocator_cpace = ChannelFrame::Cpace {
        side: Side::Allocator,
        control: allocator_control.clone(),
        message: allocator_body.clone(),
    };
    let claimant_cpace = ChannelFrame::Cpace {
        side: Side::Claimant,
        control: claimant_control.clone(),
        message: claimant_body.clone(),
    };
    let allocator_frame_bytes =
        encode_channel_frame(&allocator_cpace).expect("allocator CPace frame");
    let claimant_frame_bytes = encode_channel_frame(&claimant_cpace).expect("claimant CPace frame");

    let mut allocator_monitor =
        BootstrapMonitor::new(&invitation_bytes).expect("allocator monitor");
    let mut claimant_monitor = BootstrapMonitor::new(&invitation_bytes).expect("claimant monitor");
    let allocator_hash = allocator_monitor
        .admit(
            BootstrapPerformative::CpaceA,
            &allocator_control,
            &allocator_body,
        )
        .expect("allocator local control")
        .content_hash()
        .to_owned();
    let claimant_hash = allocator_monitor
        .admit(
            BootstrapPerformative::CpaceB,
            &claimant_control,
            &claimant_body,
        )
        .expect("allocator peer control")
        .content_hash()
        .to_owned();
    claimant_monitor
        .admit(
            BootstrapPerformative::CpaceA,
            &allocator_control,
            &allocator_body,
        )
        .expect("claimant peer control");
    claimant_monitor
        .admit(
            BootstrapPerformative::CpaceB,
            &claimant_control,
            &claimant_body,
        )
        .expect("claimant local control");

    let allocator_pending = PendingChannel::new_pairing(
        Side::Allocator,
        allocator_isk,
        invitation,
        mailbox_id,
        &allocator_frame_bytes,
        &claimant_frame_bytes,
    )
    .expect("allocator pending channel");
    let claimant_pending = PendingChannel::new_pairing(
        Side::Claimant,
        claimant_isk,
        invitation,
        mailbox_id,
        &allocator_frame_bytes,
        &claimant_frame_bytes,
    )
    .expect("claimant pending channel");
    let context = PairingContext::derive(invitation, mailbox_id).expect("pairing context");
    let mut allocator_record = InvitationRecord::new(&invitation_bytes);
    allocator_record
        .bind(mailbox_id, &claimant_frame_bytes, context.channel_context())
        .expect("allocator invitation bind");
    let mut claimant_record = InvitationRecord::new(&invitation_bytes);
    claimant_record
        .bind(
            mailbox_id,
            &allocator_frame_bytes,
            context.channel_context(),
        )
        .expect("claimant invitation bind");

    let allocator = EndpointReducer::new(
        Side::Allocator,
        &invitation_bytes,
        allocator_record,
        allocator_key,
        allocator_monitor,
        allocator_pending,
        allocator_hash.clone(),
        claimant_hash.clone(),
        allocator_profile,
    )
    .expect("allocator endpoint");
    let claimant = EndpointReducer::new(
        Side::Claimant,
        &invitation_bytes,
        claimant_record,
        claimant_key,
        claimant_monitor,
        claimant_pending,
        allocator_hash,
        claimant_hash,
        claimant_profile,
    )
    .expect("claimant endpoint");
    Endpoints {
        allocator,
        claimant,
        allocator_cpace,
        claimant_cpace,
    }
}

fn route_frame(
    sender: &mut Client,
    receiver: &mut Client,
    seq: u8,
    frame: &ChannelFrame,
) -> ChannelFrame {
    let body = encode_channel_frame(frame).expect("channel-frame encoding");
    sender.send(&ClientMessage::Put {
        seq,
        body: body.clone(),
    });
    assert_eq!(sender.receive(), ServerMessage::Acknowledged { seq });
    assert_eq!(
        receiver.receive(),
        ServerMessage::Frame {
            peer_seq: seq,
            body: body.clone(),
        }
    );
    assert_eq!(
        receiver.roundtrip(&ClientMessage::Ack { peer_seq: seq }),
        ServerMessage::Acknowledged { seq }
    );
    decode_channel_frame(&body).expect("routed channel frame")
}

fn send_effect(effects: &[EndpointEffect]) -> ChannelFrame {
    effects
        .iter()
        .find_map(|effect| match effect {
            EndpointEffect::SendFrame(frame) => Some(frame.clone()),
            _ => None,
        })
        .expect("send-frame effect")
}

fn run_profile(address: &str, kind: ProfileKind) -> ProfileResult {
    let mut allocator_client = Client::connect(address);
    let mut claimant_client = Client::connect(address);
    assert_eq!(
        allocator_client.roundtrip(&ClientMessage::Bind),
        ServerMessage::Welcome
    );
    let locator_mode = match kind {
        ProfileKind::Agent => 1,
        ProfileKind::Credential => 0,
    };
    let allocation = allocator_client.roundtrip(&ClientMessage::Allocate {
        locator_mode,
        ttl_seconds: Some(60),
    });
    let (mailbox_id, nameplate) = match allocation {
        ServerMessage::Allocated {
            mailbox_id,
            nameplate,
            ..
        } => (mailbox_id, nameplate),
        other => panic!("unexpected allocation: {other:?}"),
    };
    assert_eq!(nameplate.is_some(), kind == ProfileKind::Agent);
    assert_eq!(
        claimant_client.roundtrip(&ClientMessage::Bind),
        ServerMessage::Welcome
    );
    let locator = match kind {
        ProfileKind::Agent => Locator::Nameplate(nameplate.expect("nameplate")),
        ProfileKind::Credential => Locator::Direct(mailbox_id),
    };
    assert!(matches!(
        claimant_client.roundtrip(&ClientMessage::Claim(locator)),
        ServerMessage::Claimed {
            mailbox_id: claimed,
            ..
        } if claimed == mailbox_id
    ));

    let inputs = profile_inputs(kind, mailbox_id, nameplate);
    let (allocator_profile, claimant_profile, claimant_calls) = profile(kind);
    let Endpoints {
        mut allocator,
        mut claimant,
        allocator_cpace,
        claimant_cpace,
    } = endpoints(
        &inputs.invitation,
        mailbox_id,
        allocator_profile,
        claimant_profile,
    );

    assert_eq!(
        route_frame(
            &mut allocator_client,
            &mut claimant_client,
            0,
            &allocator_cpace,
        ),
        allocator_cpace
    );
    assert_eq!(
        route_frame(
            &mut claimant_client,
            &mut allocator_client,
            0,
            &claimant_cpace,
        ),
        claimant_cpace
    );

    let allocator_finished = allocator
        .local_finished_frame()
        .expect("allocator Finished")
        .expect("allocator Finished valid");
    let claimant_finished = claimant
        .local_finished_frame()
        .expect("claimant Finished")
        .expect("claimant Finished valid");
    let allocator_finished = route_frame(
        &mut allocator_client,
        &mut claimant_client,
        1,
        &allocator_finished,
    );
    assert!(claimant
        .receive_frame(&allocator_finished)
        .expect("claimant confirms")
        .is_empty());
    let claimant_finished = route_frame(
        &mut claimant_client,
        &mut allocator_client,
        1,
        &claimant_finished,
    );
    let opener = send_effect(
        &allocator
            .receive_frame(&claimant_finished)
            .expect("allocator confirms"),
    );
    let opener = route_frame(&mut allocator_client, &mut claimant_client, 2, &opener);
    assert!(claimant
        .receive_frame(&opener)
        .expect("claimant role opener")
        .is_empty());

    let intent = allocator
        .send_intent(&inputs.intent)
        .expect("allocator intent");
    let intent = route_frame(&mut allocator_client, &mut claimant_client, 3, &intent);
    let display = claimant
        .receive_frame(&intent)
        .expect("claimant intent")
        .into_iter()
        .find_map(|effect| match effect {
            EndpointEffect::DisplayIntent(display) => Some(display),
            _ => None,
        })
        .expect("display effect");

    let approval = send_effect(&claimant.decide(Decision::Approve).expect("approval"));
    let approval = route_frame(&mut claimant_client, &mut allocator_client, 2, &approval);
    assert!(allocator
        .receive_frame(&approval)
        .expect("allocator approval")
        .is_empty());
    let payload = ApplicationPayload {
        intent_digest: allocator.intent_digest().expect("intent digest"),
        payload_type: inputs.payload_type.into(),
        body: inputs.payload_body,
    };
    let payload = allocator.send_payload(&payload).expect("payload");
    let payload = route_frame(&mut allocator_client, &mut claimant_client, 4, &payload);
    let grant = claimant
        .receive_frame(&payload)
        .expect("claimant payload")
        .into_iter()
        .find_map(|effect| match effect {
            EndpointEffect::DeliverGrant(grant) => Some(grant),
            _ => None,
        })
        .expect("grant effect");

    allocator_client.send(&ClientMessage::Close);
    assert_eq!(
        allocator_client.receive(),
        ServerMessage::Closed(cbcl_pairing::wire::CloseReason::Closed)
    );
    assert_eq!(
        claimant_client.receive(),
        ServerMessage::Closed(cbcl_pairing::wire::CloseReason::Closed)
    );

    ProfileResult {
        kind,
        display,
        grant,
        allocator_invitation: allocator.invitation_status(),
        claimant_invitation: claimant.invitation_status(),
        claimant_verifier_calls: claimant_calls.load(Ordering::SeqCst),
        claimant_deliveries: claimant.delivered_payloads(),
        terminal: claimant.terminal_reason(),
    }
}

fn run_operator(index: u8) -> (Vec<ProfileResult>, String) {
    let relay = RelayProcess::start(index);
    let results = [ProfileKind::Agent, ProfileKind::Credential]
        .into_iter()
        .map(|kind| run_profile(&relay.address, kind))
        .collect();
    let stderr = relay.stop();
    (results, stderr)
}

#[test]
fn test_017_two_isolated_relay_processes_complete_both_profiles_identically() {
    let (first, first_log) = run_operator(0x11);
    let (second, second_log) = run_operator(0x99);
    assert_eq!(first, second);
    for result in first {
        assert_eq!(result.allocator_invitation, InvitationStatus::Spent);
        assert_eq!(result.claimant_invitation, InvitationStatus::Spent);
        assert_eq!(result.claimant_verifier_calls, 1);
        assert_eq!(result.claimant_deliveries, 1);
        assert_eq!(result.terminal, None);
    }
    for log in [first_log, second_log] {
        assert!(log.contains("operation=Allocate outcome=Success"));
        assert!(log.contains("operation=Put outcome=Success"));
        assert!(log.contains("operation=Ack outcome=Success"));
        for forbidden in [
            AGENT_APPLICATION,
            CREDENTIAL_APPLICATION,
            "alice@example.test",
            "build-runner-7",
            "wallet.example",
            "project-dispatch",
            "account-scoped credential",
            "signed SPEC-061 project grant",
        ] {
            assert!(!log.contains(forbidden), "relay log exposed {forbidden}");
        }
    }
}

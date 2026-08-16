//! Loopback-only browser demonstration of one complete agent-pairing ceremony.

use cbcl_core::message::CausedBy;
use cbcl_pairing::{
    cbcl_protocol::{
        build_bootstrap_control, BootstrapMonitor, BootstrapPerformative, CeremonySigningKey,
    },
    channel::PendingChannel,
    context::PairingContext,
    cpace,
    endpoint::{EndpointEffect, EndpointReducer, InvitationRecord},
    profile::{
        AgentGrant, AgentIntentClaims, AgentProfile, AgentWordPair, DisplayIntent, GrantVerifier,
        ProfileError, RecognisedPayload, AGENT_ACTION, AGENT_APPLICATION, AGENT_PAYLOAD,
    },
    wire::{
        encode_channel_frame, encode_cpace_message, encode_invitation, ApplicationPayload,
        ChannelFrame, Decision, Invitation, Locator, PairingIntent, Side,
    },
};
use serde_json::{json, Value};
use std::{
    env,
    error::Error,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

const DEFAULT_LISTEN: &str = "127.0.0.1:8088";
const RELAY_ORIGIN: &str = "https://relay.demo.invalid";
const INDEX_HTML: &str = include_str!("web-demo/index.html");
const APP_JS: &str = include_str!("web-demo/app.js");
const STYLE_CSS: &str = include_str!("web-demo/style.css");
const MAX_REQUEST_HEAD: usize = 16 * 1024;

type DemoResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct DemoVerifier;

impl GrantVerifier for DemoVerifier {
    fn verify(&mut self, _payload: &RecognisedPayload) -> Result<(), ProfileError> {
        Ok(())
    }
}

struct DemoCeremony {
    allocator: EndpointReducer,
    claimant: EndpointReducer,
    claims: AgentIntentClaims,
    carrier: Value,
    intent: Value,
    timeline: Vec<Value>,
}

impl DemoCeremony {
    fn start() -> DemoResult<Self> {
        let mailbox_id = random_array::<32>()?;
        let word_pair = AgentWordPair::from_csprng_octets(random_array::<3>()?);
        let words = word_pair.words();
        let nameplate = u32::from_be_bytes(random_array::<4>()?) % 1_000_000_000;
        let invitation_value = Invitation {
            application: AGENT_APPLICATION.into(),
            relay_origin: RELAY_ORIGIN.into(),
            locator: Locator::Nameplate(nameplate),
            secret: word_pair.secret().to_vec(),
            expected_allocator_key: None,
            expected_claimant_key: None,
        };
        let invitation = encode_invitation(&invitation_value)?;
        let ceremony = cbcl_pairing::cbcl_protocol::ceremony_id(&invitation);

        let allocator_key = CeremonySigningKey::from_secret(random_array::<32>()?)?;
        let claimant_key = CeremonySigningKey::from_secret(random_array::<32>()?)?;
        let (allocator_state, allocator_message) = cpace::start_pairing(
            Side::Allocator,
            &invitation_value,
            mailbox_id,
            random_array::<32>()?,
        )?;
        let (claimant_state, claimant_message) = cpace::start_pairing(
            Side::Claimant,
            &invitation_value,
            mailbox_id,
            random_array::<32>()?,
        )?;
        let allocator_isk = cpace::finish(allocator_state, &claimant_message)?;
        let claimant_isk = cpace::finish(claimant_state, &allocator_message)?;

        let allocator_body = encode_cpace_message(&allocator_message)?;
        let claimant_body = encode_cpace_message(&claimant_message)?;
        let allocator_control = build_bootstrap_control(
            &allocator_key,
            BootstrapPerformative::CpaceA,
            &ceremony,
            &allocator_body,
            CausedBy::Begin,
        )?;
        let claimant_control = build_bootstrap_control(
            &claimant_key,
            BootstrapPerformative::CpaceB,
            &ceremony,
            &claimant_body,
            CausedBy::Begin,
        )?;
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
        let allocator_frame_bytes = encode_channel_frame(&allocator_cpace)?;
        let claimant_frame_bytes = encode_channel_frame(&claimant_cpace)?;

        let mut allocator_monitor = BootstrapMonitor::new(&invitation)?;
        let mut claimant_monitor = BootstrapMonitor::new(&invitation)?;
        let allocator_hash = allocator_monitor
            .admit(
                BootstrapPerformative::CpaceA,
                &allocator_control,
                &allocator_body,
            )?
            .content_hash()
            .to_owned();
        let claimant_hash = allocator_monitor
            .admit(
                BootstrapPerformative::CpaceB,
                &claimant_control,
                &claimant_body,
            )?
            .content_hash()
            .to_owned();
        claimant_monitor.admit(
            BootstrapPerformative::CpaceA,
            &allocator_control,
            &allocator_body,
        )?;
        claimant_monitor.admit(
            BootstrapPerformative::CpaceB,
            &claimant_control,
            &claimant_body,
        )?;

        let allocator_pending = PendingChannel::new_pairing(
            Side::Allocator,
            allocator_isk,
            &invitation_value,
            mailbox_id,
            &allocator_frame_bytes,
            &claimant_frame_bytes,
        )?;
        let claimant_pending = PendingChannel::new_pairing(
            Side::Claimant,
            claimant_isk,
            &invitation_value,
            mailbox_id,
            &allocator_frame_bytes,
            &claimant_frame_bytes,
        )?;
        let allocator_record = bound_record(
            &invitation,
            &invitation_value,
            mailbox_id,
            &claimant_frame_bytes,
        )?;
        let claimant_record = bound_record(
            &invitation,
            &invitation_value,
            mailbox_id,
            &allocator_frame_bytes,
        )?;

        let mut allocator = EndpointReducer::new(
            Side::Allocator,
            &invitation,
            allocator_record,
            allocator_key,
            allocator_monitor,
            allocator_pending,
            allocator_hash.clone(),
            claimant_hash.clone(),
            Box::new(AgentProfile::new(Box::new(DemoVerifier))),
        )?;
        let mut claimant = EndpointReducer::new(
            Side::Claimant,
            &invitation,
            claimant_record,
            claimant_key,
            claimant_monitor,
            claimant_pending,
            allocator_hash,
            claimant_hash,
            Box::new(AgentProfile::new(Box::new(DemoVerifier))),
        )?;

        let mut timeline = vec![
            frame_event("CPace A", "Allocator", "Claimant", &allocator_cpace)?,
            frame_event("CPace B", "Claimant", "Allocator", &claimant_cpace)?,
        ];
        let allocator_finished = allocator
            .local_finished_frame()?
            .ok_or_else(|| demo_error("allocator Finished remained causally unknown"))?;
        let claimant_finished = claimant
            .local_finished_frame()?
            .ok_or_else(|| demo_error("claimant Finished remained causally unknown"))?;
        timeline.push(frame_event(
            "Finished A",
            "Allocator",
            "Claimant",
            &allocator_finished,
        )?);
        timeline.push(frame_event(
            "Finished B",
            "Claimant",
            "Allocator",
            &claimant_finished,
        )?);
        claimant.receive_frame(&allocator_finished)?;
        let opener = effect_frame(&allocator.receive_frame(&claimant_finished)?)?;
        timeline.push(frame_event(
            "Authenticated role cast",
            "Allocator",
            "Claimant",
            &opener,
        )?);
        claimant.receive_frame(&opener)?;
        if !allocator.session_ready() || !claimant.session_ready() {
            return Err(demo_error("role-projected session did not activate").into());
        }

        let claims = AgentIntentClaims {
            channel: "Demo workspace".into(),
            claimed_principal: "alice@example.test".into(),
            agent_handle: "research-agent-7".into(),
            requested_grant: "send and receive project messages".into(),
        };
        let (allocator_claim, claimant_claim) = claims.encode()?;
        let pairing_intent = PairingIntent {
            application: AGENT_APPLICATION.into(),
            action: AGENT_ACTION.into(),
            allocator_claim,
            claimant_claim,
            authority_summary: "Allow this agent to exchange project messages".into(),
            intent_nonce: random_array::<32>()?,
        };
        let intent_frame = allocator.send_intent(&pairing_intent)?;
        timeline.push(frame_event(
            "Sealed intent",
            "Allocator",
            "Claimant",
            &intent_frame,
        )?);
        let display = effect_display(&claimant.receive_frame(&intent_frame)?)?;

        Ok(Self {
            allocator,
            claimant,
            claims,
            carrier: json!({
                "relay": RELAY_ORIGIN,
                "nameplate": nameplate.to_string(),
                "words": [words[0], words[1]],
                "entropyBits": 22,
                "note": "The invitation travels out of band; the relay never receives these words."
            }),
            intent: display_json(&display),
            timeline,
        })
    }

    fn snapshot(&self) -> Value {
        snapshot(
            "awaiting-decision",
            "Authenticated intent ready",
            &self.carrier,
            &self.intent,
            &self.timeline,
            Value::Null,
        )
    }

    fn finish(&mut self, decision: Decision) -> DemoResult<Value> {
        let decision_effects = self.claimant.decide(decision)?;
        let decision_frame = effect_frame(&decision_effects)?;
        let label = match decision {
            Decision::Approve => "Sealed approval",
            Decision::Decline => "Sealed decline",
        };
        self.timeline.push(frame_event(
            label,
            "Claimant",
            "Allocator",
            &decision_frame,
        )?);
        self.allocator.receive_frame(&decision_frame)?;

        match decision {
            Decision::Decline => Ok(snapshot(
                "declined",
                "Pairing declined safely",
                &self.carrier,
                &self.intent,
                &self.timeline,
                json!({
                    "kind": "declined",
                    "message": "No payload or grant was released. Both endpoints erased their secret state.",
                    "allocatorSecretsErased": self.allocator.secrets_erased(),
                    "claimantSecretsErased": self.claimant.secrets_erased()
                }),
            )),
            Decision::Approve => {
                let digest = self
                    .allocator
                    .intent_digest()
                    .ok_or_else(|| demo_error("allocator retained no intent digest"))?;
                let payload = ApplicationPayload {
                    intent_digest: digest,
                    payload_type: AGENT_PAYLOAD.into(),
                    body: AgentGrant {
                        claimed_principal: self.claims.claimed_principal.clone(),
                        agent_handle: self.claims.agent_handle.clone(),
                        requested_grant: self.claims.requested_grant.clone(),
                        grant: b"demo-only application grant".to_vec(),
                    }
                    .encode()?,
                };
                let payload_frame = self.allocator.send_payload(&payload)?;
                self.timeline.push(frame_event(
                    "Sealed grant payload",
                    "Allocator",
                    "Claimant",
                    &payload_frame,
                )?);
                let grant = effect_grant(&self.claimant.receive_frame(&payload_frame)?)?;
                Ok(snapshot(
                    "grant-delivered",
                    "Approved grant verified",
                    &self.carrier,
                    &self.intent,
                    &self.timeline,
                    json!({
                        "kind": "approved",
                        "message": "One intent-bound payload reached the application verifier.",
                        "application": grant.application,
                        "payloadType": grant.payload_type,
                        "bodyBytes": grant.body.len(),
                        "deliveredPayloads": self.claimant.delivered_payloads(),
                        "verifierCalls": self.claimant.profile_verifications(),
                        "next": "The application shell now acknowledges and closes the demo mailbox."
                    }),
                ))
            }
        }
    }
}

struct DemoApp {
    ceremony: Option<DemoCeremony>,
    public_state: Value,
}

impl DemoApp {
    fn new() -> Self {
        Self {
            ceremony: None,
            public_state: idle_snapshot(),
        }
    }

    fn start(&mut self) -> DemoResult<Value> {
        let ceremony = DemoCeremony::start()?;
        let state = ceremony.snapshot();
        self.ceremony = Some(ceremony);
        self.public_state = state.clone();
        Ok(state)
    }

    fn decide(&mut self, decision: Decision) -> DemoResult<Value> {
        let mut ceremony = self
            .ceremony
            .take()
            .ok_or_else(|| demo_error("start a fresh pairing ceremony first"))?;
        let state = ceremony.finish(decision)?;
        self.public_state = state.clone();
        Ok(state)
    }

    fn reset(&mut self) -> Value {
        self.ceremony = None;
        self.public_state = idle_snapshot();
        self.public_state.clone()
    }
}

fn main() -> DemoResult<()> {
    let address = env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_LISTEN.to_owned())
        .parse::<SocketAddr>()?;
    if !address.ip().is_loopback() {
        return Err(demo_error("the demo server only binds loopback addresses").into());
    }
    let listener = TcpListener::bind(address)?;
    let local = listener.local_addr()?;
    println!("cbcl-pairing web demo: http://{local}");
    println!("experimental and loopback-only; press Ctrl-C to stop");
    let mut app = DemoApp::new();
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                if let Err(error) = handle_connection(stream, &mut app) {
                    eprintln!("demo request failed: {error}");
                }
            }
            Err(error) => eprintln!("demo connection failed: {error}"),
        }
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, app: &mut DemoApp) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.len() > MAX_REQUEST_HEAD {
            return write_response(
                &mut stream,
                "431 Request Header Fields Too Large",
                "application/json; charset=utf-8",
                &json!({"error": "request headers are too large"}).to_string(),
            );
        }
    }
    let head_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| demo_error("incomplete HTTP request"))?;
    let head = std::str::from_utf8(&request[..head_end])
        .map_err(|_| demo_error("request head is not UTF-8"))?;
    let mut request_parts = head
        .lines()
        .next()
        .ok_or_else(|| demo_error("missing request line"))?
        .split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| demo_error("missing request method"))?;
    let path = request_parts
        .next()
        .ok_or_else(|| demo_error("missing request path"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| demo_error("missing HTTP version"))?;
    if request_parts.next().is_some() || version != "HTTP/1.1" {
        return write_json_error(&mut stream, "400 Bad Request", "invalid request line");
    }

    match (method, path) {
        ("GET", "/") => write_response(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            INDEX_HTML,
        ),
        ("GET", "/app.js") => write_response(
            &mut stream,
            "200 OK",
            "text/javascript; charset=utf-8",
            APP_JS,
        ),
        ("GET", "/style.css") => {
            write_response(&mut stream, "200 OK", "text/css; charset=utf-8", STYLE_CSS)
        }
        ("GET", "/api/state") => write_json(&mut stream, "200 OK", &app.public_state),
        ("POST", "/api/start") => match app.start() {
            Ok(value) => write_json(&mut stream, "200 OK", &value),
            Err(error) => {
                write_json_error(&mut stream, "500 Internal Server Error", &error.to_string())
            }
        },
        ("POST", "/api/approve") => match app.decide(Decision::Approve) {
            Ok(value) => write_json(&mut stream, "200 OK", &value),
            Err(error) => write_json_error(&mut stream, "409 Conflict", &error.to_string()),
        },
        ("POST", "/api/decline") => match app.decide(Decision::Decline) {
            Ok(value) => write_json(&mut stream, "200 OK", &value),
            Err(error) => write_json_error(&mut stream, "409 Conflict", &error.to_string()),
        },
        ("POST", "/api/reset") => write_json(&mut stream, "200 OK", &app.reset()),
        ("GET", _) => write_json_error(&mut stream, "404 Not Found", "route not found"),
        _ => write_json_error(&mut stream, "405 Method Not Allowed", "method not allowed"),
    }
}

fn write_json(stream: &mut TcpStream, status: &str, value: &Value) -> io::Result<()> {
    write_response(
        stream,
        status,
        "application/json; charset=utf-8",
        &value.to_string(),
    )
}

fn write_json_error(stream: &mut TcpStream, status: &str, message: &str) -> io::Result<()> {
    write_json(stream, status, &json!({ "error": message }))
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

fn bound_record(
    invitation: &[u8],
    invitation_value: &Invitation,
    mailbox_id: [u8; 32],
    peer_frame: &[u8],
) -> DemoResult<InvitationRecord> {
    let context = PairingContext::derive(invitation_value, mailbox_id)?;
    let mut record = InvitationRecord::new(invitation);
    record.bind(mailbox_id, peer_frame, context.channel_context())?;
    Ok(record)
}

fn frame_event(label: &str, from: &str, to: &str, frame: &ChannelFrame) -> DemoResult<Value> {
    let size = encode_channel_frame(frame)?.len();
    Ok(json!({
        "label": label,
        "from": from,
        "to": to,
        "bytes": size,
        "relayView": format!("opaque {size}-byte body; protocol meaning hidden")
    }))
}

fn snapshot(
    stage: &str,
    headline: &str,
    carrier: &Value,
    intent: &Value,
    timeline: &[Value],
    outcome: Value,
) -> Value {
    let opaque_bytes: u64 = timeline
        .iter()
        .filter_map(|event| event.get("bytes").and_then(Value::as_u64))
        .sum();
    json!({
        "stage": stage,
        "headline": headline,
        "carrier": carrier,
        "intent": intent,
        "relay": {
            "frames": timeline.len(),
            "opaqueBytes": opaque_bytes,
            "sees": ["network addresses", "mailbox identifier", "timing", "frame sizes", "expiry"],
            "cannotSee": ["invitation words", "application", "intent", "decision", "grant"],
            "note": "This page labels frame meaning using endpoint-side demo instrumentation. A real relay sees only opaque bytes."
        },
        "timeline": timeline,
        "outcome": outcome
    })
}

fn idle_snapshot() -> Value {
    json!({
        "stage": "idle",
        "headline": "Ready to create an invitation",
        "carrier": null,
        "intent": null,
        "relay": {
            "frames": 0,
            "opaqueBytes": 0,
            "sees": ["network addresses", "mailbox identifier", "timing", "frame sizes", "expiry"],
            "cannotSee": ["invitation words", "application", "intent", "decision", "grant"],
            "note": "The demo runs both endpoints in one Rust process and instruments the relay boundary."
        },
        "timeline": [],
        "outcome": null
    })
}

fn display_json(display: &DisplayIntent) -> Value {
    json!({
        "application": display.application,
        "action": display.action,
        "authoritySummary": display.authority_summary,
        "fields": display.fields.iter().map(|field| json!({
            "label": field.label,
            "value": field.value,
            "claimedBySecretHolder": field.claimed_by_secret_holder
        })).collect::<Vec<_>>()
    })
}

fn effect_frame(effects: &[EndpointEffect]) -> DemoResult<ChannelFrame> {
    effects
        .iter()
        .find_map(|effect| match effect {
            EndpointEffect::SendFrame(frame) => Some(frame.clone()),
            _ => None,
        })
        .ok_or_else(|| demo_error("endpoint emitted no frame").into())
}

fn effect_display(effects: &[EndpointEffect]) -> DemoResult<DisplayIntent> {
    effects
        .iter()
        .find_map(|effect| match effect {
            EndpointEffect::DisplayIntent(display) => Some(display.clone()),
            _ => None,
        })
        .ok_or_else(|| demo_error("endpoint emitted no display intent").into())
}

fn effect_grant(effects: &[EndpointEffect]) -> DemoResult<cbcl_pairing::profile::AuthorisedGrant> {
    effects
        .iter()
        .find_map(|effect| match effect {
            EndpointEffect::DeliverGrant(grant) => Some(grant.clone()),
            _ => None,
        })
        .ok_or_else(|| demo_error("endpoint emitted no authorised grant").into())
}

fn random_array<const N: usize>() -> io::Result<[u8; N]> {
    let mut value = [0_u8; N];
    getrandom::fill(&mut value)
        .map_err(|error| demo_error(&format!("operating-system randomness failed: {error}")))?;
    Ok(value)
}

fn demo_error(message: &str) -> io::Error {
    io::Error::other(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_runs_the_real_pairing_and_releases_one_grant() {
        let mut app = DemoApp::new();
        let started = app.start().expect("start demo");
        assert_eq!(started["stage"], "awaiting-decision");
        assert_eq!(started["carrier"]["entropyBits"], 22);
        let nameplate = started["carrier"]["nameplate"]
            .as_str()
            .expect("display nameplate");
        assert_eq!(
            nameplate
                .parse::<u32>()
                .expect("numeric nameplate")
                .to_string(),
            nameplate
        );
        assert_eq!(started["intent"]["application"], AGENT_APPLICATION);
        assert_eq!(started["relay"]["frames"], 6);

        let approved = app.decide(Decision::Approve).expect("approve demo");
        assert_eq!(approved["stage"], "grant-delivered");
        assert_eq!(approved["outcome"]["deliveredPayloads"], 1);
        assert_eq!(approved["outcome"]["verifierCalls"], 1);
        assert_eq!(approved["relay"]["frames"], 8);
    }

    #[test]
    fn decline_releases_no_payload_and_erases_both_endpoints() {
        let mut app = DemoApp::new();
        app.start().expect("start demo");
        let declined = app.decide(Decision::Decline).expect("decline demo");
        assert_eq!(declined["stage"], "declined");
        assert_eq!(declined["outcome"]["kind"], "declined");
        assert_eq!(declined["outcome"]["allocatorSecretsErased"], true);
        assert_eq!(declined["outcome"]["claimantSecretsErased"], true);
        assert_eq!(declined["relay"]["frames"], 7);
    }
}

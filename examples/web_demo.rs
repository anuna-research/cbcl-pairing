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
    relay::sample_nameplate,
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
const MAX_REQUEST_BODY: usize = 1024;

type DemoResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct DemoVerifier;

impl GrantVerifier for DemoVerifier {
    fn verify(&mut self, _payload: &RecognisedPayload) -> Result<(), ProfileError> {
        Ok(())
    }
}

struct DemoInvitation {
    mailbox_id: [u8; 32],
    invitation: Invitation,
    carrier: Value,
}

impl DemoInvitation {
    fn allocate() -> DemoResult<Self> {
        let mailbox_id = random_array::<32>()?;
        let word_pair = AgentWordPair::from_csprng_octets(random_array::<3>()?);
        let words = word_pair.words();
        let nameplate = sample_nameplate(|| random_array::<4>().map(u32::from_be_bytes))?;
        Ok(Self {
            mailbox_id,
            invitation: Invitation {
                application: AGENT_APPLICATION.into(),
                relay_origin: RELAY_ORIGIN.into(),
                locator: Locator::Nameplate(nameplate),
                secret: word_pair.secret().to_vec(),
                expected_allocator_key: None,
                expected_claimant_key: None,
            },
            carrier: json!({
                "relay": RELAY_ORIGIN,
                "nameplate": nameplate.to_string(),
                "words": [words[0], words[1]],
                "entropyBits": 22,
                "note": "Give the nameplate and both words to the claimant out of band. The relay later sees the public nameplate, but never the words."
            }),
        })
    }

    fn snapshot(&self) -> Value {
        snapshot(
            "invitation-created",
            "Invitation ready for claimant",
            &self.carrier,
            &Value::Null,
            &[],
            Value::Null,
        )
    }

    fn failed_snapshot(&self) -> Value {
        snapshot(
            "failed",
            "Invitation consumed after key mismatch",
            &self.carrier,
            &Value::Null,
            &[],
            json!({
                "kind": "failed",
                "message": "Those valid invitation words did not match. No intent, payload, or grant was released.",
                "next": "This invitation allowed one online guess and is now consumed. Start fresh to try again."
            }),
        )
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
    fn start(pending: DemoInvitation) -> DemoResult<Self> {
        let DemoInvitation {
            mailbox_id,
            invitation: invitation_value,
            carrier,
        } = pending;
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
            carrier,
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
    invitation: Option<DemoInvitation>,
    ceremony: Option<DemoCeremony>,
    public_state: Value,
}

impl DemoApp {
    fn new() -> Self {
        Self {
            invitation: None,
            ceremony: None,
            public_state: idle_snapshot(),
        }
    }

    fn start(&mut self) -> DemoResult<Value> {
        let invitation = DemoInvitation::allocate()?;
        let state = invitation.snapshot();
        self.invitation = Some(invitation);
        self.ceremony = None;
        self.public_state = state.clone();
        Ok(state)
    }

    fn claim(&mut self, nameplate: u32, words: AgentWordPair) -> DemoResult<Value> {
        let pending = self
            .invitation
            .as_ref()
            .ok_or_else(|| demo_error("create a fresh invitation first"))?;
        if !matches!(pending.invitation.locator, Locator::Nameplate(value) if value == nameplate) {
            return Err(demo_error("that nameplate does not resolve this invitation").into());
        }

        let invitation = self
            .invitation
            .take()
            .expect("the pending invitation was just borrowed");
        if words.secret().to_vec() != invitation.invitation.secret {
            let state = invitation.failed_snapshot();
            self.ceremony = None;
            self.public_state = state.clone();
            return Ok(state);
        }

        let ceremony = DemoCeremony::start(invitation)?;
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
        self.invitation = None;
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
        if request.len() > MAX_REQUEST_HEAD
            && !request.windows(4).any(|window| window == b"\r\n\r\n")
        {
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
    if head_end > MAX_REQUEST_HEAD {
        return write_json_error(
            &mut stream,
            "431 Request Header Fields Too Large",
            "request headers are too large",
        );
    }
    let (method, path, content_length) = {
        let head = std::str::from_utf8(&request[..head_end])
            .map_err(|_| demo_error("request head is not UTF-8"))?;
        let mut lines = head.lines();
        let mut request_parts = lines
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

        let mut content_length = None;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                return write_json_error(&mut stream, "400 Bad Request", "invalid header line");
            };
            if name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return write_json_error(
                        &mut stream,
                        "400 Bad Request",
                        "duplicate Content-Length",
                    );
                }
                content_length = Some(match value.trim().parse::<usize>() {
                    Ok(length) => length,
                    Err(_) => {
                        return write_json_error(
                            &mut stream,
                            "400 Bad Request",
                            "Content-Length must be an unsigned decimal integer",
                        );
                    }
                });
            }
        }
        (
            method.to_owned(),
            path.to_owned(),
            content_length.unwrap_or(0),
        )
    };

    if content_length > MAX_REQUEST_BODY {
        return write_json_error(
            &mut stream,
            "413 Content Too Large",
            "request body is too large",
        );
    }
    let body_start = head_end + 4;
    while request.len() < body_start + content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return write_json_error(&mut stream, "400 Bad Request", "incomplete request body");
        }
        request.extend_from_slice(&chunk[..read]);
    }
    let body = &request[body_start..body_start + content_length];

    match (method.as_str(), path.as_str()) {
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
        ("POST", "/api/claim") => {
            let (nameplate, first, second) = match parse_claim_entry(body) {
                Ok(entry) => entry,
                Err(error) => {
                    return write_json_error(&mut stream, "400 Bad Request", &error.to_string());
                }
            };
            let words = match AgentWordPair::recognise(&first, &second) {
                Ok(words) => words,
                Err(_) => {
                    return write_json_error(
                        &mut stream,
                        "422 Unprocessable Entity",
                        "enter two exact lowercase English BIP-39 words",
                    );
                }
            };
            match app.claim(nameplate, words) {
                Ok(value) => write_json(&mut stream, "200 OK", &value),
                Err(error) => write_json_error(&mut stream, "409 Conflict", &error.to_string()),
            }
        }
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
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

fn parse_claim_entry(body: &[u8]) -> io::Result<(u32, String, String)> {
    let Value::Object(mut fields) = serde_json::from_slice::<Value>(body)
        .map_err(|_| demo_error("claim body must be valid JSON"))?
    else {
        return Err(demo_error("claim body must be a JSON object"));
    };
    if fields.len() != 3 {
        return Err(demo_error(
            "claim body must contain only nameplate, first, and second",
        ));
    }
    let nameplate = fields
        .remove("nameplate")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| demo_error("nameplate must be a string"))?;
    let first = fields
        .remove("first")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| demo_error("first must be a string"))?;
    let second = fields
        .remove("second")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| demo_error("second must be a string"))?;
    if first.is_empty() || second.is_empty() || first.len() > 32 || second.len() > 32 {
        return Err(demo_error(
            "each invitation word must contain 1 to 32 bytes",
        ));
    }
    let parsed_nameplate = nameplate
        .parse::<u32>()
        .map_err(|_| demo_error("nameplate must be a natural decimal number"))?;
    if parsed_nameplate > 999_999_999 || parsed_nameplate.to_string() != nameplate {
        return Err(demo_error(
            "nameplate must be canonical decimal in 0..999999999",
        ));
    }
    Ok((parsed_nameplate, first, second))
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
            "sees": ["network addresses", "mailbox/nameplate locator", "timing", "frame sizes", "expiry"],
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
            "sees": ["network addresses", "mailbox/nameplate locator", "timing", "frame sizes", "expiry"],
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
        assert_eq!(started["stage"], "invitation-created");
        assert_eq!(started["carrier"]["entropyBits"], 22);
        assert_eq!(started["relay"]["frames"], 0);
        assert!(started["intent"].is_null());
        let displayed_nameplate = started["carrier"]["nameplate"]
            .as_str()
            .expect("display nameplate");
        assert_eq!(
            displayed_nameplate
                .parse::<u32>()
                .expect("numeric nameplate")
                .to_string(),
            displayed_nameplate
        );

        let paired = app
            .claim(carrier_nameplate(&started), carrier_words(&started))
            .expect("enter invitation");
        assert_eq!(paired["stage"], "awaiting-decision");
        assert_eq!(paired["intent"]["application"], AGENT_APPLICATION);
        assert_eq!(paired["relay"]["frames"], 6);

        let approved = app.decide(Decision::Approve).expect("approve demo");
        assert_eq!(approved["stage"], "grant-delivered");
        assert_eq!(approved["outcome"]["deliveredPayloads"], 1);
        assert_eq!(approved["outcome"]["verifierCalls"], 1);
        assert_eq!(approved["relay"]["frames"], 8);
    }

    #[test]
    fn decline_releases_no_payload_and_erases_both_endpoints() {
        let mut app = DemoApp::new();
        let started = app.start().expect("start demo");
        app.claim(carrier_nameplate(&started), carrier_words(&started))
            .expect("enter invitation");
        let declined = app.decide(Decision::Decline).expect("decline demo");
        assert_eq!(declined["stage"], "declined");
        assert_eq!(declined["outcome"]["kind"], "declined");
        assert_eq!(declined["outcome"]["allocatorSecretsErased"], true);
        assert_eq!(declined["outcome"]["claimantSecretsErased"], true);
        assert_eq!(declined["relay"]["frames"], 7);
    }

    #[test]
    fn invalid_dictionary_word_can_be_corrected_before_online_attempt() {
        let mut app = DemoApp::new();
        let started = app.start().expect("start demo");

        assert!(AgentWordPair::recognise("not-a-word", "ability").is_err());
        let paired = app
            .claim(carrier_nameplate(&started), carrier_words(&started))
            .expect("pending invitation remains usable");
        assert_eq!(paired["stage"], "awaiting-decision");
    }

    #[test]
    fn unresolved_nameplate_can_be_corrected_without_consuming_the_invitation() {
        let mut app = DemoApp::new();
        let started = app.start().expect("start demo");
        let nameplate = carrier_nameplate(&started);
        let wrong_nameplate = if nameplate == 999_999_999 {
            nameplate - 1
        } else {
            nameplate + 1
        };

        assert!(app.claim(wrong_nameplate, carrier_words(&started)).is_err());
        let paired = app
            .claim(nameplate, carrier_words(&started))
            .expect("corrected nameplate uses pending invitation");
        assert_eq!(paired["stage"], "awaiting-decision");
    }

    #[test]
    fn valid_wrong_words_consume_the_single_attempt_without_revealing_intent() {
        let mut app = DemoApp::new();
        let started = app.start().expect("start demo");
        let displayed = started["carrier"]["words"]
            .as_array()
            .expect("displayed word array");
        let candidate = if displayed[0] == "abandon" && displayed[1] == "ability" {
            AgentWordPair::recognise("able", "about").expect("alternate valid words")
        } else {
            AgentWordPair::recognise("abandon", "ability").expect("valid words")
        };

        let failed = app
            .claim(carrier_nameplate(&started), candidate)
            .expect("consume wrong attempt");
        assert_eq!(failed["stage"], "failed");
        assert_eq!(failed["outcome"]["kind"], "failed");
        assert!(failed["intent"].is_null());
        assert_eq!(failed["relay"]["frames"], 0);
        assert!(app
            .claim(carrier_nameplate(&started), carrier_words(&started))
            .is_err());
    }

    #[test]
    fn claimant_json_accepts_only_canonical_nameplate_and_two_words() {
        assert_eq!(
            parse_claim_entry(br#"{"nameplate":"123456","first":"abandon","second":"ability"}"#)
                .expect("valid claim"),
            (123_456, "abandon".to_owned(), "ability".to_owned())
        );
        assert!(parse_claim_entry(
            br#"{"nameplate":"123456","first":"abandon","second":"ability","extra":1}"#
        )
        .is_err());
        assert!(parse_claim_entry(
            br#"{"nameplate":"001234","first":"abandon","second":"ability"}"#
        )
        .is_err());
        assert!(
            parse_claim_entry(br#"{"nameplate":1234,"first":"abandon","second":"ability"}"#)
                .is_err()
        );
        assert!(parse_claim_entry(br#"["123456","abandon","ability"]"#).is_err());
    }

    fn carrier_nameplate(state: &Value) -> u32 {
        state["carrier"]["nameplate"]
            .as_str()
            .expect("displayed nameplate")
            .parse()
            .expect("canonical numeric nameplate")
    }

    fn carrier_words(state: &Value) -> AgentWordPair {
        let words = state["carrier"]["words"]
            .as_array()
            .expect("displayed word array");
        AgentWordPair::recognise(
            words[0].as_str().expect("first displayed word"),
            words[1].as_str().expect("second displayed word"),
        )
        .expect("generated words are canonical")
    }
}

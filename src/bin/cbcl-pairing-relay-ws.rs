//! Binary-WebSocket shell for the application-unaware SPEC-072 relay.
//!
//! Each WebSocket binary message is exactly one deterministic-CBOR client or
//! server message. TLS remains an operator boundary; bind this process to a
//! private address behind authenticated WSS termination.

mod common;
use common::{Admission, BudgetStream};

use cbcl_pairing::{
    limiter::{LimiterConfig, OperationPolicy},
    observability::CapacityCaps,
    relay::{
        sample_nameplate, ConnectionId, RelayConfig, RelayRandomness, RelayService, RoutedMessage,
    },
    storage::FileMailboxStore,
    wire::{decode_client_message, encode_server_message, ServerMessage},
};
use std::{
    collections::BTreeMap,
    env, fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tungstenite::{accept_hdr_with_config, Message, WebSocket};

const MAX_WIRE_MESSAGE: usize = 70_000;
const DEFAULT_LIMIT: u32 = 240;
const DEFAULT_WINDOW_SECONDS: u64 = 60;
const DEFAULT_LIMITER_CAP: usize = 100_000;
const DEFAULT_MAILBOX_CAP: u64 = 10_000;
const DEFAULT_QUEUE_CAP: u64 = 512 * 1024 * 1024;

#[derive(Debug)]
struct Args {
    listen: SocketAddr,
    operator_key_file: PathBuf,
    store_dir: Option<PathBuf>,
    conformance_allocation: bool,
    check_config: bool,
    emergency_close: bool,
    allowed_origins: Vec<String>,
    allow_missing_origin: bool,
}

type Senders = Arc<Mutex<BTreeMap<ConnectionId, SyncSender<ServerMessage>>>>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("relay_startup outcome=invalid detail={error}");
            ExitCode::from(78)
        }
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let config = RelayConfig {
        operator_key: read_operator_key(&args.operator_key_file)?,
        limiter: LimiterConfig::new(
            OperationPolicy {
                limit: DEFAULT_LIMIT,
                window_seconds: DEFAULT_WINDOW_SECONDS,
            },
            DEFAULT_LIMITER_CAP,
            30,
        ),
        capacity: CapacityCaps {
            open_mailboxes: DEFAULT_MAILBOX_CAP,
            queue_bytes: DEFAULT_QUEUE_CAP,
            limiter_entries: DEFAULT_LIMITER_CAP as u64,
        },
        allocation_enabled: args.conformance_allocation,
    };
    let mut service = match &args.store_dir {
        Some(directory) => RelayService::with_store(
            config,
            Box::new(FileMailboxStore::open(directory).map_err(|error| error.to_string())?),
        ),
        None => RelayService::new(config),
    }
    .map_err(|error| error.to_string())?;
    if args.emergency_close {
        if args.store_dir.is_none() {
            return Err("--emergency-close requires --store-dir".into());
        }
        service
            .emergency_close(unix_time())
            .map_err(|error| error.to_string())?;
        println!("EMERGENCY CLOSE OK allocation=disabled");
        return Ok(());
    }
    if args.check_config {
        println!("CONFIG OK allocation=disabled-by-default transport=websocket");
        return Ok(());
    }

    let listener = TcpListener::bind(args.listen).map_err(|error| error.to_string())?;
    println!(
        "LISTEN ws://{}/",
        listener.local_addr().map_err(|error| error.to_string())?
    );
    let service = Arc::new(Mutex::new(service));
    let senders: Senders = Arc::new(Mutex::new(BTreeMap::new()));
    spawn_sweeper(Arc::clone(&service), Arc::clone(&senders));
    let admission = Admission::new();
    let next_connection = AtomicU64::new(1);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("relay_event operation=accept outcome=invalid detail={error}");
                continue;
            }
        };
        let Ok(stream) = admission.admit(stream) else {
            continue;
        };
        let connection = ConnectionId(next_connection.fetch_add(1, Ordering::Relaxed));
        let service = Arc::clone(&service);
        let senders = Arc::clone(&senders);
        let origins = args.allowed_origins.clone();
        let allow_missing = args.allow_missing_origin;
        let _ = thread::Builder::new().spawn(move || {
            serve_connection(stream, connection, service, senders, origins, allow_missing)
        });
    }
    Ok(())
}

// tungstenite fixes the callback error type to an HTTP response.
#[allow(clippy::result_large_err)]
fn serve_connection(
    stream: BudgetStream,
    connection: ConnectionId,
    service: Arc<Mutex<RelayService>>,
    senders: Senders,
    origins: Vec<String>,
    allow_missing: bool,
) {
    let peer = stream
        .stream
        .peer_addr()
        .map(|address| address.ip().to_string().into_bytes())
        .unwrap_or_else(|_| b"unknown-peer".to_vec());
    let _ = stream.stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut config = tungstenite::protocol::WebSocketConfig::default();
    config.max_message_size = Some(MAX_WIRE_MESSAGE);
    config.max_frame_size = Some(MAX_WIRE_MESSAGE);
    let Ok(mut websocket) = accept_hdr_with_config(
        stream,
        |request: &tungstenite::handshake::server::Request, response| {
            let values = request.headers().get_all("origin");
            let mut values = values.iter();
            let accepted = match values.next() {
                None => allow_missing,
                Some(value) => {
                    values.next().is_none()
                        && value
                            .to_str()
                            .ok()
                            .is_some_and(|origin| origins.iter().any(|allowed| allowed == origin))
                }
            };
            if accepted {
                Ok(response)
            } else {
                Err(tungstenite::http::Response::builder()
                    .status(403)
                    .body(Some("Origin refused".into()))
                    .expect("fixed response"))
            }
        },
        Some(config),
    ) else {
        return;
    };
    let _ = websocket
        .get_mut()
        .stream
        .set_read_timeout(Some(Duration::from_millis(100)));
    let (sender, receiver) = mpsc::sync_channel(16);
    if let Ok(mut table) = senders.lock() {
        table.insert(connection, sender);
    } else {
        return;
    }

    let mut invalid = 0;
    loop {
        if !flush_outbound(&mut websocket, &receiver) {
            break;
        }
        match websocket.read() {
            Ok(Message::Binary(bytes)) => {
                if websocket.get_ref().charge().is_err() {
                    break;
                }
                let message = match decode_client_message(&bytes) {
                    Ok(message) => message,
                    Err(_) => {
                        dispatch(
                            &senders,
                            vec![RoutedMessage {
                                connection,
                                message: ServerMessage::Error(400),
                            }],
                        );
                        invalid += 1;
                        if invalid >= 3 {
                            break;
                        }
                        continue;
                    }
                };
                websocket.get_ref().progress();
                let randomness = match random_values() {
                    Ok(randomness) => randomness,
                    Err(()) => {
                        dispatch(
                            &senders,
                            vec![RoutedMessage {
                                connection,
                                message: ServerMessage::Error(503),
                            }],
                        );
                        continue;
                    }
                };
                let now = unix_time();
                let (expired, replies, log) = match service.lock() {
                    Ok(mut relay) => {
                        let expired = relay.sweep(now).unwrap_or_default();
                        let replies = relay
                            .handle(connection, &peer, now, randomness, message)
                            .unwrap_or_else(|_| {
                                vec![RoutedMessage {
                                    connection,
                                    message: ServerMessage::Error(503),
                                }]
                            });
                        (expired, replies, relay.last_log_event())
                    }
                    Err(_) => break,
                };
                if let Some(log) = log {
                    eprintln!(
                        "relay_event operation={:?} outcome={:?}",
                        log.operation, log.outcome
                    );
                }
                dispatch(&senders, expired);
                dispatch(&senders, replies);
            }
            Ok(Message::Text(_)) => {
                if websocket.get_ref().charge().is_err() {
                    break;
                }
                invalid += 1;
                dispatch(
                    &senders,
                    vec![RoutedMessage {
                        connection,
                        message: ServerMessage::Error(400),
                    }],
                );
                if invalid >= 3 {
                    break;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {
                if websocket.get_ref().charge().is_err() {
                    break;
                }
            }
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(tungstenite::Error::Capacity(
                tungstenite::error::CapacityError::MessageTooLong { .. },
            )) => {
                if let Ok(bytes) = encode_server_message(&ServerMessage::Error(413)) {
                    let _ = websocket.send(Message::Binary(bytes.into()));
                }
                break;
            }
            Err(_) => break,
        }
    }
    if let Ok(mut relay) = service.lock() {
        relay.disconnect(connection);
    }
    if let Ok(mut table) = senders.lock() {
        table.remove(&connection);
    }
}

fn flush_outbound(
    websocket: &mut WebSocket<BudgetStream>,
    receiver: &Receiver<ServerMessage>,
) -> bool {
    loop {
        match receiver.try_recv() {
            Ok(message) => {
                let Ok(bytes) = encode_server_message(&message) else {
                    return false;
                };
                if websocket.send(Message::Binary(bytes.into())).is_err() {
                    return false;
                }
            }
            Err(TryRecvError::Empty) => return true,
            Err(TryRecvError::Disconnected) => return false,
        }
    }
}

fn dispatch(senders: &Senders, messages: Vec<RoutedMessage>) {
    let Ok(mut table) = senders.lock() else {
        return;
    };
    for routed in messages {
        if let Some(sender) = table.get(&routed.connection) {
            if sender.try_send(routed.message).is_err() {
                table.remove(&routed.connection);
            }
        }
    }
}

fn spawn_sweeper(service: Arc<Mutex<RelayService>>, senders: Senders) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        let expired = match service.lock() {
            Ok(mut relay) => relay.sweep(unix_time()).unwrap_or_default(),
            Err(_) => return,
        };
        dispatch(&senders, expired);
    });
}

fn parse_args() -> Result<Args, String> {
    let mut listen = None;
    let mut operator_key_file = None;
    let mut store_dir = None;
    let mut conformance_allocation = false;
    let mut check_config = false;
    let mut emergency_close = false;
    let mut allowed_origins = Vec::new();
    let mut allow_missing_origin = false;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--allow-origin" => {
                let origin = args.next().ok_or("--allow-origin requires an origin")?;
                let parsed = url::Url::parse(&origin).map_err(|_| "invalid origin")?;
                if !matches!(parsed.scheme(), "http" | "https") || parsed.origin().ascii_serialization() != origin {
                    return Err("origin must be canonical http(s) scheme://host[:port]".into());
                }
                allowed_origins.push(origin);
            }
            "--allow-missing-origin" => allow_missing_origin = true,
            "--listen" => listen = Some(args.next().ok_or("--listen requires an address")?.parse().map_err(|_| "invalid --listen address")?),
            "--operator-key-file" => operator_key_file = Some(PathBuf::from(args.next().ok_or("--operator-key-file requires a path")?)),
            "--store-dir" => store_dir = Some(PathBuf::from(args.next().ok_or("--store-dir requires a path")?)),
            "--enable-conformance-allocation" => conformance_allocation = true,
            "--check-config" => check_config = true,
            "--emergency-close" => emergency_close = true,
            "--help" | "-h" => return Err("usage: cbcl-pairing-relay-ws --listen ADDR --operator-key-file PATH [--store-dir DIR] [--enable-conformance-allocation] [--check-config] [--emergency-close] [--allow-origin ORIGIN] [--allow-missing-origin]".into()),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(Args {
        listen: listen.ok_or("missing --listen")?,
        operator_key_file: operator_key_file.ok_or("missing --operator-key-file")?,
        store_dir,
        conformance_allocation,
        check_config,
        emergency_close,
        allowed_origins,
        allow_missing_origin,
    })
}

fn read_operator_key(path: &Path) -> Result<[u8; 32], String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)
            .map_err(|error| format!("operator key: {error}"))?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err("operator key file must not be accessible by group or others".into());
        }
    }
    let bytes = fs::read(path).map_err(|error| format!("operator key: {error}"))?;
    if bytes.len() == 32 {
        return bytes
            .try_into()
            .map_err(|_| "operator key must be 32 octets".into());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "operator key must be raw 32 octets or lowercase hex")?
        .trim_end_matches(['\r', '\n']);
    if text.len() != 64 {
        return Err("operator key must be raw 32 octets or 64 hex digits".into());
    }
    let mut key = [0_u8; 32];
    for (index, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
        key[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(key)
}

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("operator key hex must be lowercase".into()),
    }
}

fn random_values() -> Result<RelayRandomness, ()> {
    let mut bytes = [0_u8; 64];
    getrandom::fill(&mut bytes).map_err(|_| ())?;
    let nameplate = sample_nameplate(|| {
        let mut candidate = [0_u8; 4];
        getrandom::fill(&mut candidate).map_err(|_| ())?;
        Ok(u32::from_be_bytes(candidate))
    })?;
    Ok(RelayRandomness {
        mailbox_id: bytes[..32].try_into().map_err(|_| ())?,
        membership_token: bytes[32..64].try_into().map_err(|_| ())?,
        nameplate,
    })
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

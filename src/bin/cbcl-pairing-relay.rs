//! Reference length-delimited TCP shell for the blind relay service.
//!
//! Production allocation remains disabled. The explicit conformance flag is
//! for local tests while the human cryptography and interoperability gates are
//! open. A deployment terminates TLS/WSS in front of this private listener.

use cbcl_pairing::{
    limiter::{LimiterConfig, OperationPolicy},
    observability::CapacityCaps,
    relay::{ConnectionId, RelayConfig, RelayRandomness, RelayService, RoutedMessage},
    wire::{decode_client_message, encode_server_message, ServerMessage},
};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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
    conformance_allocation: bool,
    check_config: bool,
}

type Writers = Arc<Mutex<BTreeMap<ConnectionId, Arc<Mutex<TcpStream>>>>>;

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
    let operator_key = read_operator_key(&args.operator_key_file)?;
    let service = RelayService::new(RelayConfig {
        operator_key,
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
    })
    .map_err(|error| error.to_string())?;
    if args.check_config {
        println!("CONFIG OK allocation=disabled-by-default");
        return Ok(());
    }

    let listener = TcpListener::bind(args.listen).map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    println!("LISTEN {address}");
    io::stdout().flush().map_err(|error| error.to_string())?;

    let service = Arc::new(Mutex::new(service));
    let writers: Writers = Arc::new(Mutex::new(BTreeMap::new()));
    spawn_sweeper(Arc::clone(&service), Arc::clone(&writers));
    let next_connection = AtomicU64::new(1);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(value) => value,
            Err(error) => {
                eprintln!("relay_event operation=accept outcome=invalid detail={error}");
                continue;
            }
        };
        let connection = ConnectionId(next_connection.fetch_add(1, Ordering::Relaxed));
        let peer = stream
            .peer_addr()
            .map(|address| address.ip().to_string().into_bytes())
            .unwrap_or_else(|_| b"unknown-peer".to_vec());
        let writer = stream.try_clone().map_err(|error| error.to_string())?;
        writers
            .lock()
            .map_err(|_| "writer lock poisoned".to_owned())?
            .insert(connection, Arc::new(Mutex::new(writer)));
        let service = Arc::clone(&service);
        let writers = Arc::clone(&writers);
        thread::spawn(move || serve_connection(stream, connection, peer, service, writers));
    }
    Ok(())
}

fn parse_args() -> Result<Args, String> {
    let mut listen = None;
    let mut operator_key_file = None;
    let mut conformance_allocation = false;
    let mut check_config = false;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--listen" => {
                let value = args.next().ok_or("--listen requires an address")?;
                listen = Some(value.parse().map_err(|_| "invalid --listen address")?);
            }
            "--operator-key-file" => {
                operator_key_file = Some(PathBuf::from(
                    args.next().ok_or("--operator-key-file requires a path")?,
                ));
            }
            "--enable-conformance-allocation" => conformance_allocation = true,
            "--check-config" => check_config = true,
            "--help" | "-h" => {
                return Err(
                    "usage: cbcl-pairing-relay --listen ADDR --operator-key-file PATH [--enable-conformance-allocation] [--check-config]".into(),
                );
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(Args {
        listen: listen.ok_or("missing --listen")?,
        operator_key_file: operator_key_file.ok_or("missing --operator-key-file")?,
        conformance_allocation,
        check_config,
    })
}

fn read_operator_key(path: &Path) -> Result<[u8; 32], String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|error| format!("operator key: {error}"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
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
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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

fn serve_connection(
    mut reader: TcpStream,
    connection: ConnectionId,
    peer: Vec<u8>,
    service: Arc<Mutex<RelayService>>,
    writers: Writers,
) {
    loop {
        let bytes = match read_message(&mut reader) {
            Ok(Some(value)) => value,
            Ok(None) => break,
            Err(_) => {
                send_one(
                    &writers,
                    RoutedMessage {
                        connection,
                        message: ServerMessage::Error(400),
                    },
                );
                break;
            }
        };
        let message = match decode_client_message(&bytes) {
            Ok(value) => value,
            Err(_) => {
                send_one(
                    &writers,
                    RoutedMessage {
                        connection,
                        message: ServerMessage::Error(400),
                    },
                );
                continue;
            }
        };
        let now = unix_time();
        let randomness = match random_values() {
            Ok(value) => value,
            Err(()) => {
                send_one(
                    &writers,
                    RoutedMessage {
                        connection,
                        message: ServerMessage::Error(503),
                    },
                );
                continue;
            }
        };
        let (expired, replies, log) = {
            let mut service = match service.lock() {
                Ok(value) => value,
                Err(_) => break,
            };
            let expired = service.sweep(now).unwrap_or_default();
            let replies = service
                .handle(connection, &peer, now, randomness, message)
                .unwrap_or_else(|_| {
                    vec![RoutedMessage {
                        connection,
                        message: ServerMessage::Error(503),
                    }]
                });
            (expired, replies, service.last_log_event())
        };
        if let Some(log) = log {
            eprintln!(
                "relay_event operation={:?} outcome={:?}",
                log.operation, log.outcome
            );
        }
        send_all(&writers, expired);
        send_all(&writers, replies);
    }
    if let Ok(mut service) = service.lock() {
        service.disconnect(connection);
    }
    if let Ok(mut writers) = writers.lock() {
        writers.remove(&connection);
    }
}

fn spawn_sweeper(service: Arc<Mutex<RelayService>>, writers: Writers) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        let messages = service
            .lock()
            .ok()
            .and_then(|mut service| service.sweep(unix_time()).ok())
            .unwrap_or_default();
        send_all(&writers, messages);
    });
}

fn read_message(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0_u8; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_WIRE_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wire message length",
        ));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

fn send_all(writers: &Writers, messages: Vec<RoutedMessage>) {
    for message in messages {
        send_one(writers, message);
    }
}

fn send_one(writers: &Writers, routed: RoutedMessage) {
    let writer = writers
        .lock()
        .ok()
        .and_then(|writers| writers.get(&routed.connection).cloned());
    let Some(writer) = writer else {
        return;
    };
    let Ok(bytes) = encode_server_message(&routed.message) else {
        return;
    };
    if let Ok(mut writer) = writer.lock() {
        let _ = writer.write_all(&(bytes.len() as u32).to_be_bytes());
        let _ = writer.write_all(&bytes);
        let _ = writer.flush();
    };
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_values() -> Result<RelayRandomness, ()> {
    let mut bytes = [0_u8; 68];
    getrandom::fill(&mut bytes).map_err(|_| ())?;
    let mut mailbox_id = [0_u8; 32];
    mailbox_id.copy_from_slice(&bytes[..32]);
    let mut membership_token = [0_u8; 32];
    membership_token.copy_from_slice(&bytes[32..64]);
    let nameplate = u32::from_be_bytes(bytes[64..68].try_into().map_err(|_| ())?) % 1_000_000_000;
    Ok(RelayRandomness {
        mailbox_id,
        membership_token,
        nameplate,
    })
}

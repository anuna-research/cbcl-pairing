//! Binary WebSocket transport conformance for the reference relay.

#![cfg(feature = "relay")]

use cbcl_pairing::wire::{
    decode_server_message, encode_client_message, ClientMessage, Locator, ServerMessage,
};
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};
use tungstenite::{connect, Message, WebSocket};

static NEXT_KEY_FILE: AtomicU64 = AtomicU64::new(0);

struct RelayProcess {
    child: Child,
    address: String,
    key_file: PathBuf,
}

impl RelayProcess {
    fn start() -> Self {
        Self::start_policy(true)
    }

    fn start_policy(allow_missing: bool) -> Self {
        let key_file = std::env::temp_dir().join(format!(
            "cbcl-pairing-ws-test-{}-{}.key",
            std::process::id(),
            NEXT_KEY_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&key_file, [0x91; 32]).expect("operator key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_cbcl-pairing-relay-ws"))
            .args([
                "--listen",
                "127.0.0.1:0",
                "--operator-key-file",
                key_file.to_str().unwrap(),
                "--enable-conformance-allocation",
                "--allow-origin",
                "https://approved.example",
            ])
            .args(if allow_missing {
                vec!["--allow-missing-origin"]
            } else {
                vec![]
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn WebSocket relay");
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let address = line.strip_prefix("LISTEN ").unwrap_or_else(|| {
            let _ = child.wait();
            let mut stderr = String::new();
            if let Some(mut stream) = child.stderr.take() {
                stream.read_to_string(&mut stderr).unwrap();
            }
            panic!("WebSocket relay did not announce a listener: stdout={line:?} stderr={stderr:?}")
        });
        let address = address.trim().to_owned();
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
        if let Some(mut stream) = self.child.stderr.take() {
            stream.read_to_string(&mut stderr).unwrap();
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

fn send<S: Read + std::io::Write>(websocket: &mut WebSocket<S>, message: &ClientMessage) {
    websocket
        .send(Message::Binary(
            encode_client_message(message).unwrap().into(),
        ))
        .unwrap();
}

fn receive<S: Read + std::io::Write>(websocket: &mut WebSocket<S>) -> ServerMessage {
    loop {
        match websocket.read().unwrap() {
            Message::Binary(bytes) => return decode_server_message(&bytes).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("non-binary relay response: {other:?}"),
        }
    }
}

#[test]
fn websocket_shell_carries_exact_cbor_and_routes_asynchronously() {
    let process = RelayProcess::start();
    let (mut allocator, _) = connect(&process.address).expect("allocator WebSocket");
    send(&mut allocator, &ClientMessage::Bind);
    assert_eq!(receive(&mut allocator), ServerMessage::Welcome);
    send(
        &mut allocator,
        &ClientMessage::Allocate {
            locator_mode: 0,
            ttl_seconds: Some(60),
        },
    );
    let ServerMessage::Allocated {
        mailbox_id,
        membership_token: allocator_token,
        ..
    } = receive(&mut allocator)
    else {
        panic!("allocation response")
    };

    let (mut claimant, _) = connect(&process.address).expect("claimant WebSocket");
    send(&mut claimant, &ClientMessage::Bind);
    assert_eq!(receive(&mut claimant), ServerMessage::Welcome);
    send(
        &mut claimant,
        &ClientMessage::Claim(Locator::Direct(mailbox_id)),
    );
    let ServerMessage::Claimed {
        membership_token: claimant_token,
        ..
    } = receive(&mut claimant)
    else {
        panic!("claim response")
    };
    assert_ne!(allocator_token, claimant_token);

    send(
        &mut allocator,
        &ClientMessage::Put {
            seq: 0,
            body: b"opaque websocket frame".to_vec(),
        },
    );
    assert_eq!(
        receive(&mut allocator),
        ServerMessage::Acknowledged { seq: 0 }
    );
    assert_eq!(
        receive(&mut claimant),
        ServerMessage::Frame {
            peer_seq: 0,
            body: b"opaque websocket frame".to_vec(),
        }
    );

    claimant.send(Message::Text("not CBOR".into())).unwrap();
    assert_eq!(receive(&mut claimant), ServerMessage::Error(400));
    let logs = process.stop();
    assert!(!logs.contains(&hex::encode(mailbox_id)));
    assert!(!logs.contains("opaque websocket frame"));
}

#[test]
fn test_027_oversize_websocket_message_returns_413_before_close() {
    let process = RelayProcess::start();
    let (mut websocket, _) = connect(&process.address).expect("WebSocket");
    websocket
        .send(Message::Binary(vec![0_u8; 70_001].into()))
        .expect("send oversize message");
    assert_eq!(receive(&mut websocket), ServerMessage::Error(413));
    let _ = process.stop();
}

#[test]
fn websocket_origin_policy_requires_exact_allowlist_match() {
    use tungstenite::client::IntoClientRequest;
    let process = RelayProcess::start();
    for origin in [
        "https://hostile.example",
        "null",
        "https://approved.example:444",
        "https://APPROVED.example",
    ] {
        let mut request = process.address.as_str().into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Origin", origin.parse().unwrap());
        assert!(
            matches!(connect(request), Err(tungstenite::Error::Http(response)) if response.status() == 403)
        );
    }
    let mut request = process.address.as_str().into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Origin", "https://approved.example".parse().unwrap());
    let (mut socket, _) = connect(request).unwrap();
    send(&mut socket, &ClientMessage::Bind);
    assert_eq!(receive(&mut socket), ServerMessage::Welcome);
}

#[test]
fn malformed_websocket_messages_close_after_three_attempts() {
    let process = RelayProcess::start();
    let (mut socket, _) = connect(&process.address).unwrap();
    for _ in 0..2 {
        socket.send(Message::Binary(vec![0xff].into())).unwrap();
        assert_eq!(receive(&mut socket), ServerMessage::Error(400));
    }
    socket.send(Message::Text("invalid".into())).unwrap();
    assert!(socket.read().is_err());
}

#[test]
fn idle_websocket_releases_its_connection() {
    let process = RelayProcess::start();
    let (mut socket, _) = connect(&process.address).unwrap();
    send(&mut socket, &ClientMessage::Bind);
    assert_eq!(receive(&mut socket), ServerMessage::Welcome);
    if let tungstenite::stream::MaybeTlsStream::Plain(stream) = socket.get_mut() {
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(33)))
            .unwrap();
    }
    let started = std::time::Instant::now();
    assert!(socket.read().is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(32));
}

#[test]
fn websocket_default_refuses_missing_origin_and_stalled_upgrade_expires() {
    let process = RelayProcess::start_policy(false);
    assert!(
        matches!(connect(&process.address), Err(tungstenite::Error::Http(response)) if response.status() == 403)
    );
    let address = process
        .address
        .strip_prefix("ws://")
        .unwrap()
        .trim_end_matches('/');
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(7)))
        .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
}

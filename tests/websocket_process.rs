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
            ])
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

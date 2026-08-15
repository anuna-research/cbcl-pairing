//! Local two-process portion of SPEC-072 TEST-017.

#![cfg(feature = "relay")]

use cbcl_pairing::wire::{
    decode_server_message, encode_client_message, ClientMessage, Locator, ServerMessage,
};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
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

fn run_operator(index: u8) -> (Vec<&'static str>, String) {
    let relay = RelayProcess::start(index);
    let mut allocator = Client::connect(&relay.address);
    let mut claimant = Client::connect(&relay.address);
    let mut results = Vec::new();

    assert_eq!(
        allocator.roundtrip(&ClientMessage::Bind),
        ServerMessage::Welcome
    );
    results.push("allocator-bound");
    let allocation = allocator.roundtrip(&ClientMessage::Allocate {
        locator_mode: 0,
        ttl_seconds: Some(60),
    });
    let (mailbox_id, allocator_token) = match allocation {
        ServerMessage::Allocated {
            mailbox_id,
            membership_token,
            nameplate: None,
            ..
        } => (mailbox_id, membership_token),
        other => panic!("unexpected allocation: {other:?}"),
    };
    assert_ne!(mailbox_id, [0; 32]);
    assert_ne!(allocator_token, [0; 32]);
    results.push("allocated");

    assert_eq!(
        claimant.roundtrip(&ClientMessage::Bind),
        ServerMessage::Welcome
    );
    results.push("claimant-bound");
    let claim = claimant.roundtrip(&ClientMessage::Claim(Locator::Direct(mailbox_id)));
    match claim {
        ServerMessage::Claimed {
            mailbox_id: claimed,
            membership_token,
            ..
        } => {
            assert_eq!(claimed, mailbox_id);
            assert_ne!(membership_token, allocator_token);
        }
        other => panic!("unexpected claim: {other:?}"),
    }
    results.push("claimed");

    for (seq, body, label) in [
        (0, b"agent-profile opaque bytes".as_slice(), "agent-routed"),
        (
            1,
            b"credential-profile opaque bytes".as_slice(),
            "credential-routed",
        ),
    ] {
        allocator.send(&ClientMessage::Put {
            seq,
            body: body.to_vec(),
        });
        assert_eq!(allocator.receive(), ServerMessage::Acknowledged { seq });
        assert_eq!(
            claimant.receive(),
            ServerMessage::Frame {
                peer_seq: seq,
                body: body.to_vec(),
            }
        );
        results.push(label);
    }

    drop(allocator);
    drop(claimant);
    let stderr = relay.stop();
    (results, stderr)
}

#[test]
fn test_017_two_isolated_relay_processes_route_both_profiles_identically() {
    let (first, first_log) = run_operator(0x11);
    let (second, second_log) = run_operator(0x99);
    assert_eq!(first, second);
    for log in [first_log, second_log] {
        assert!(log.contains("operation=Allocate outcome=Success"));
        assert!(log.contains("operation=Put outcome=Success"));
        assert!(!log.contains("agent-profile opaque bytes"));
        assert!(!log.contains("credential-profile opaque bytes"));
        assert!(!log.contains("application"));
    }
}

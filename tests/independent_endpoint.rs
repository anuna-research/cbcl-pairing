//! SPEC-072 TEST-018 cross-language endpoint vector gate.

use cbcl_core::message::CausedBy;
use cbcl_pairing::{
    cbcl_protocol::{
        build_bootstrap_control, BootstrapMonitor, BootstrapPerformative, CeremonySigningKey,
        ProtocolError, ProtocolVerdict,
    },
    channel::{ChannelError, PendingChannel},
    context::PairingContext,
    cpace::{finish, start, IntermediateSessionKey},
    wire::{
        encode_channel_frame, encode_cpace_message, encode_invitation, ChannelFrame, CpaceMessage,
        Direction, Invitation, Locator, Side,
    },
};
use serde_json::Value;
use std::process::Command;

fn hx(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(bytes)
}
fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn official_isks() -> (IntermediateSessionKey, IntermediateSessionKey) {
    let sid = hex::decode("7e4b4791d6a8ef019b936c79fb7f2c57").unwrap();
    let ya = hex::decode("21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080")
        .unwrap()
        .try_into()
        .unwrap();
    let yb = hex::decode("848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a")
        .unwrap()
        .try_into()
        .unwrap();
    let (a, am) = start(
        Side::Allocator,
        b"Password",
        b"\x0bA_initiator\x0bB_responder",
        &sid,
        b"ADa",
        ya,
    )
    .unwrap();
    let (b, bm) = start(
        Side::Claimant,
        b"Password",
        b"\x0bA_initiator\x0bB_responder",
        &sid,
        b"ADb",
        yb,
    )
    .unwrap();
    (finish(a, &bm).unwrap(), finish(b, &am).unwrap())
}

struct Fixture {
    invitation: Invitation,
    invitation_wire: Vec<u8>,
    a_frame: Vec<u8>,
    b_frame: Vec<u8>,
}

fn fixture(vector: &Value) -> Fixture {
    let invitation = Invitation {
        application: "anuna.io/credential/v1".into(),
        relay_origin: "https://relay.example".into(),
        locator: Locator::Direct(std::array::from_fn(|i| i as u8)),
        secret: (0x40..0x50).collect(),
        expected_allocator_key: None,
        expected_claimant_key: None,
    };
    let invitation_wire = encode_invitation(&invitation).unwrap();
    assert_eq!(hx(&invitation_wire), field(vector, "invitation"));
    let context = PairingContext::derive(&invitation, std::array::from_fn(|i| i as u8)).unwrap();
    assert_eq!(hx(context.channel_identifier()), field(vector, "ci"));
    assert_eq!(
        hx(context.associated_data(Side::Allocator)),
        field(vector, "ad_a")
    );
    assert_eq!(
        hx(context.associated_data(Side::Claimant)),
        field(vector, "ad_b")
    );
    assert_eq!(
        hx(context.channel_context()),
        field(vector, "public_context")
    );

    let ma = encode_cpace_message(&CpaceMessage {
        side: Side::Allocator,
        share: [0x31; 32],
        associated_data: context.associated_data(Side::Allocator).to_vec(),
    })
    .unwrap();
    let mb = encode_cpace_message(&CpaceMessage {
        side: Side::Claimant,
        share: [0x42; 32],
        associated_data: context.associated_data(Side::Claimant).to_vec(),
    })
    .unwrap();
    assert_eq!(hx(&ma), field(vector, "cpace_message_a"));
    assert_eq!(hx(&mb), field(vector, "cpace_message_b"));
    let ceremony = cbcl_pairing::cbcl_protocol::ceremony_id(&invitation_wire);
    assert_eq!(ceremony, field(vector, "ceremony"));
    let ak = CeremonySigningKey::from_secret([0x11; 32]).unwrap();
    let bk = CeremonySigningKey::from_secret([0x22; 32]).unwrap();
    let ca = build_bootstrap_control(
        &ak,
        BootstrapPerformative::CpaceA,
        &ceremony,
        &ma,
        CausedBy::Begin,
    )
    .unwrap();
    let cb = build_bootstrap_control(
        &bk,
        BootstrapPerformative::CpaceB,
        &ceremony,
        &mb,
        CausedBy::Begin,
    )
    .unwrap();
    assert_eq!(hx(&ca), field(vector, "cpace_control_a"));
    assert_eq!(hx(&cb), field(vector, "cpace_control_b"));
    let a_frame = encode_channel_frame(&ChannelFrame::Cpace {
        side: Side::Allocator,
        control: ca.clone(),
        message: ma.clone(),
    })
    .unwrap();
    let b_frame = encode_channel_frame(&ChannelFrame::Cpace {
        side: Side::Claimant,
        control: cb.clone(),
        message: mb.clone(),
    })
    .unwrap();
    assert_eq!(hx(&a_frame), field(vector, "cpace_frame_a"));
    assert_eq!(hx(&b_frame), field(vector, "cpace_frame_b"));

    let mut monitor = BootstrapMonitor::new(&invitation_wire).unwrap();
    let aa = monitor
        .admit(BootstrapPerformative::CpaceA, &ca, &ma)
        .unwrap();
    assert_eq!(aa.verdict(), ProtocolVerdict::Valid);
    assert_eq!(aa.content_hash(), field(vector, "cpace_hash_a"));
    let ha = aa.content_hash().to_owned();
    let bb = monitor
        .admit(BootstrapPerformative::CpaceB, &cb, &mb)
        .unwrap();
    assert_eq!(bb.verdict(), ProtocolVerdict::Valid);
    assert_eq!(bb.content_hash(), field(vector, "cpace_hash_b"));
    let hb = bb.content_hash().to_owned();

    let (a_isk, b_isk) = official_isks();
    let pa = PendingChannel::new_pairing(
        Side::Allocator,
        a_isk,
        &invitation,
        std::array::from_fn(|i| i as u8),
        &a_frame,
        &b_frame,
    )
    .unwrap();
    let pb = PendingChannel::new_pairing(
        Side::Claimant,
        b_isk,
        &invitation,
        std::array::from_fn(|i| i as u8),
        &a_frame,
        &b_frame,
    )
    .unwrap();
    assert_eq!(hx(pa.transcript_hash()), field(vector, "transcript_hash"));
    assert_eq!(hx(pa.local_finished()), field(vector, "finished_a"));
    assert_eq!(hx(pb.local_finished()), field(vector, "finished_b"));
    let fca = build_bootstrap_control(
        &ak,
        BootstrapPerformative::FinishedA,
        &ceremony,
        &pa.local_finished(),
        CausedBy::Multiple(vec![ha.clone(), hb.clone()]),
    )
    .unwrap();
    let fcb = build_bootstrap_control(
        &bk,
        BootstrapPerformative::FinishedB,
        &ceremony,
        &pb.local_finished(),
        CausedBy::Multiple(vec![ha, hb]),
    )
    .unwrap();
    assert_eq!(hx(&fca), field(vector, "finished_control_a"));
    assert_eq!(hx(&fcb), field(vector, "finished_control_b"));
    let admitted_fa = monitor
        .admit(BootstrapPerformative::FinishedA, &fca, &pa.local_finished())
        .unwrap();
    assert_eq!(admitted_fa.verdict(), ProtocolVerdict::Valid);
    assert_eq!(admitted_fa.content_hash(), field(vector, "finished_hash_a"));
    let admitted_fb = monitor
        .admit(BootstrapPerformative::FinishedB, &fcb, &pb.local_finished())
        .unwrap();
    assert_eq!(admitted_fb.verdict(), ProtocolVerdict::Valid);
    assert_eq!(admitted_fb.content_hash(), field(vector, "finished_hash_b"));
    assert_eq!(
        hx(encode_channel_frame(&ChannelFrame::Finished {
            side: Side::Allocator,
            control: fca,
            value: pa.local_finished()
        })
        .unwrap()),
        field(vector, "finished_frame_a")
    );
    assert_eq!(
        hx(encode_channel_frame(&ChannelFrame::Finished {
            side: Side::Claimant,
            control: fcb,
            value: pb.local_finished()
        })
        .unwrap()),
        field(vector, "finished_frame_b")
    );
    let af = pa.local_finished();
    let bf = pb.local_finished();
    let mut a = pa.confirm(&bf).unwrap();
    let mut b = pb.confirm(&af).unwrap();
    assert_eq!(hx(a.exporter()), field(vector, "exporter"));
    let sa = a.seal(b"allocator payload").unwrap();
    let sb = b.seal(b"claimant decision").unwrap();
    if let ChannelFrame::Sealed { ciphertext, .. } = &sa {
        assert_eq!(hx(ciphertext), field(vector, "ciphertext_a"));
    }
    if let ChannelFrame::Sealed { ciphertext, .. } = &sb {
        assert_eq!(hx(ciphertext), field(vector, "ciphertext_b"));
    }
    assert_eq!(
        hx(encode_channel_frame(&sa).unwrap()),
        field(vector, "sealed_frame_a")
    );
    assert_eq!(
        hx(encode_channel_frame(&sb).unwrap()),
        field(vector, "sealed_frame_b")
    );
    assert_eq!(b.open(&sa).unwrap(), b"allocator payload");
    assert_eq!(a.open(&sb).unwrap(), b"claimant decision");
    Fixture {
        invitation,
        invitation_wire,
        a_frame,
        b_frame,
    }
}

fn pending_pair(f: &Fixture) -> (PendingChannel, PendingChannel) {
    let (a, b) = official_isks();
    let mailbox = std::array::from_fn(|i| i as u8);
    (
        PendingChannel::new_pairing(
            Side::Allocator,
            a,
            &f.invitation,
            mailbox,
            &f.a_frame,
            &f.b_frame,
        )
        .unwrap(),
        PendingChannel::new_pairing(
            Side::Claimant,
            b,
            &f.invitation,
            mailbox,
            &f.a_frame,
            &f.b_frame,
        )
        .unwrap(),
    )
}

#[test]
fn test_018_independent_python_endpoint_agrees_on_every_public_vector() {
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tools/reference_endpoint.py"
        ))
        .output()
        .expect("run independent endpoint");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let vector: Value = serde_json::from_slice(&output.stdout).expect("endpoint JSON");
    let f = fixture(&vector);

    let (a, b) = pending_pair(&f);
    let mut bad = b.local_finished();
    bad[0] ^= 1;
    assert!(matches!(
        a.confirm(&bad),
        Err(ChannelError::FinishedMismatch)
    ));

    let (a, b) = pending_pair(&f);
    let af = a.local_finished();
    let bf = b.local_finished();
    let mut sender = a.confirm(&bf).unwrap();
    let mut receiver = b.confirm(&af).unwrap();
    let once = sender.seal(b"once").unwrap();
    receiver.open(&once).unwrap();
    assert_eq!(receiver.open(&once), Err(ChannelError::CounterMismatch));

    let (a, b) = pending_pair(&f);
    let af = a.local_finished();
    let bf = b.local_finished();
    let mut sender = a.confirm(&bf).unwrap();
    let mut receiver = b.confirm(&af).unwrap();
    let _ = sender.seal(b"zero").unwrap();
    let one = sender.seal(b"one").unwrap();
    assert_eq!(receiver.open(&one), Err(ChannelError::CounterMismatch));

    let (a, b) = pending_pair(&f);
    let af = a.local_finished();
    let bf = b.local_finished();
    let mut sender = a.confirm(&bf).unwrap();
    let mut receiver = b.confirm(&af).unwrap();
    let mut wrong = sender.seal(b"direction").unwrap();
    if let ChannelFrame::Sealed { direction, .. } = &mut wrong {
        *direction = Direction::ClaimantToAllocator;
    }
    assert_eq!(receiver.open(&wrong), Err(ChannelError::DirectionMismatch));

    let (a, b) = pending_pair(&f);
    let af = a.local_finished();
    let bf = b.local_finished();
    let mut sender = a.confirm(&bf).unwrap();
    let mut receiver = b.confirm(&af).unwrap();
    let mut corrupt = sender.seal(b"tag").unwrap();
    if let ChannelFrame::Sealed { ciphertext, .. } = &mut corrupt {
        ciphertext[0] ^= 1;
    }
    assert_eq!(receiver.open(&corrupt), Err(ChannelError::InvalidTag));

    let ceremony = cbcl_pairing::cbcl_protocol::ceremony_id(&f.invitation_wire);
    let key = CeremonySigningKey::from_secret([0x11; 32]).unwrap();
    let body = b"bound";
    let control = build_bootstrap_control(
        &key,
        BootstrapPerformative::CpaceA,
        &ceremony,
        body,
        CausedBy::Begin,
    )
    .unwrap();
    assert_eq!(
        BootstrapMonitor::new(&f.invitation_wire)
            .unwrap()
            .admit(BootstrapPerformative::CpaceA, &control, b"mutated")
            .unwrap_err(),
        ProtocolError::BodyBinding
    );

    let a_body = hex::decode(field(&vector, "cpace_message_a")).unwrap();
    let a_control = hex::decode(field(&vector, "cpace_control_a")).unwrap();
    let mut early_monitor = BootstrapMonitor::new(&f.invitation_wire).unwrap();
    let known = early_monitor
        .admit(BootstrapPerformative::CpaceA, &a_control, &a_body)
        .unwrap()
        .content_hash()
        .to_owned();
    let early_body = [0x55; 64];
    let early = build_bootstrap_control(
        &key,
        BootstrapPerformative::FinishedA,
        &ceremony,
        &early_body,
        CausedBy::Multiple(vec![known, format!("sha256:{}", "77".repeat(32))]),
    )
    .unwrap();
    assert_eq!(
        early_monitor
            .admit(BootstrapPerformative::FinishedA, &early, &early_body)
            .unwrap()
            .verdict(),
        ProtocolVerdict::Unknown
    );

    assert_eq!(vector["terminal"]["bad_finished"], "finished-mismatch");
    assert_eq!(vector["terminal"]["replay"], "counter-mismatch");
    assert_eq!(vector["terminal"]["gap"], "counter-mismatch");
    assert_eq!(vector["terminal"]["wrong_direction"], "direction-mismatch");
    assert_eq!(vector["terminal"]["bad_tag"], "invalid-tag");
    assert_eq!(vector["cbcl_verdicts"]["mutated_body"], "body-binding");
    assert_eq!(vector["cbcl_verdicts"]["missing_predecessor"], "unknown");
}

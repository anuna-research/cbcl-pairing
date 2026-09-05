use super::*;
#[derive(Debug)]
struct NoBodies;
impl CredentialV2BodyVerifier for NoBodies {
    fn verify(
        &mut self,
        _: &super::super::CredentialV2LogicalBody<'_>,
    ) -> Result<(), CredentialV2Error> {
        panic!("no application work before a peer")
    }
}
#[test]
fn terminal_input_erases_unconsumed_scalar_presence_and_wrapping_key() {
    let mut session = CredentialV2AllocatorSession::new(
        CredentialV2AllocatorSessionInput {
            mode: CredentialV2AllocatorMode::Manual,
            application_context: "https://a.b/a".into(),
            relay_origin: "https://r".into(),
            mailbox_id: [1; 32],
            carrier_ceremony_id: [2; 32],
            carrier_nonce: [3; 32],
            cpace_secret: *super::super::CredentialV2ManualWords::from_csprng([4; 4])
                .cpace_secret(),
            claim_token: [5; 16],
            cpace_scalar: [6; 32],
            profile_digest: [7; 32],
            expected_allocator_key: Some([8; 32]),
            checkpoint_wrapping_key: [9; 32],
        },
        Box::new(NoBodies),
    )
    .unwrap();
    assert!(session
        .receive(&[0], 1, CredentialV2CheckpointNonce::from_csprng([10; 12]))
        .is_err());
    assert!(session.presence.is_none());
    assert!(session.cpace_scalar.is_none());
    assert_eq!(*session.wrapping_key, [0; 32]);
    assert!(matches!(session.state, AllocatorState::Terminal));
}

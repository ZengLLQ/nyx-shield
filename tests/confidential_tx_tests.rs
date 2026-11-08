use curve25519_dalek::scalar::Scalar;
use nyx_shield::{
    BulletproofGenerators, ConfidentialTransaction, ProofError, StealthKeypair,
};
use rand::rngs::OsRng;

#[test]
fn test_confidential_transaction_valid_flow() {
    let mut rng = OsRng;
    let generators = BulletproofGenerators::new(128);
    let bits = 32;

    // Alice keypair (sender)
    let alice = StealthKeypair::generate(&mut rng);
    // Bob keypair (recipient)
    let bob = StealthKeypair::generate(&mut rng);

    // Alice owns two UTXOs: 60 units and 40 units (total 100)
    let in_vals = [60u64, 40u64];
    let in_blinds = [Scalar::random(&mut rng), Scalar::random(&mut rng)];
    let in_keys = [Scalar::random(&mut rng), Scalar::random(&mut rng)];

    // Alice wants to pay Bob 75 units, pay 5 units fee, and keep 20 units as change
    let recipients = [(bob.meta_address, 75u64)];
    let fee = 5u64;

    let tx = ConfidentialTransaction::create(
        &generators,
        &in_vals,
        &in_blinds,
        &in_keys,
        &recipients,
        &alice.meta_address,
        fee,
        bits,
        &mut rng,
    )
    .expect("Valid confidential transaction creation must succeed");

    assert_eq!(tx.inputs.len(), 2);
    assert_eq!(tx.outputs.len(), 2); // Bob's payment + Alice's change
    assert_eq!(tx.fee, fee);

    // Verify complete transaction: ownership + range proofs + balance signature
    let verify_res = tx.verify(&generators, bits);
    assert!(verify_res.is_ok(), "Valid confidential transaction must pass full verification");

    // Bob scans and confirms he received 75
    let bob_output = &tx.outputs[0];
    let bob_key = bob_output.recipient_stealth.scan_and_derive_spending_key(&bob);
    assert!(bob_key.is_some(), "Bob must be able to scan and claim his 75 output");

    // Alice scans and confirms she received change
    let alice_change_output = &tx.outputs[1];
    let change_key = alice_change_output.recipient_stealth.scan_and_derive_spending_key(&alice);
    assert!(change_key.is_some(), "Alice must be able to scan and claim her change output");
}

#[test]
fn test_confidential_tx_inflation_rejected() {
    let mut rng = OsRng;
    let generators = BulletproofGenerators::new(128);
    let bits = 32;

    let alice = StealthKeypair::generate(&mut rng);
    let bob = StealthKeypair::generate(&mut rng);

    let in_vals = [50u64];
    let in_blinds = [Scalar::random(&mut rng)];
    let in_keys = [Scalar::random(&mut rng)];

    // Attempt to spend 60 units from 50 units
    let recipients = [(bob.meta_address, 60u64)];
    let fee = 2u64;

    let res = ConfidentialTransaction::create(
        &generators,
        &in_vals,
        &in_blinds,
        &in_keys,
        &recipients,
        &alice.meta_address,
        fee,
        bits,
        &mut rng,
    );

    assert_eq!(res, Err(ProofError::BalanceMismatch), "Inflation transaction must be rejected");
}

#[test]
fn test_confidential_tx_tampered_signature_fails() {
    let mut rng = OsRng;
    let generators = BulletproofGenerators::new(128);
    let bits = 32;

    let alice = StealthKeypair::generate(&mut rng);
    let bob = StealthKeypair::generate(&mut rng);

    let in_vals = [100u64];
    let in_blinds = [Scalar::random(&mut rng)];
    let in_keys = [Scalar::random(&mut rng)];

    let recipients = [(bob.meta_address, 80u64)];
    let fee = 20u64;

    let mut tx = ConfidentialTransaction::create(
        &generators,
        &in_vals,
        &in_blinds,
        &in_keys,
        &recipients,
        &alice.meta_address,
        fee,
        bits,
        &mut rng,
    )
    .unwrap();

    // Tamper with balance signature
    tx.balance_signature.s_scalar += Scalar::ONE;

    let verify_res = tx.verify(&generators, bits);
    assert_eq!(verify_res, Err(ProofError::BalanceMismatch));
}

use curve25519_dalek::scalar::Scalar;
use nyx_shield::{BulletproofGenerators, ConfidentialTransaction, StealthKeypair};
use rand::rngs::OsRng;

fn main() {
    println!("================================================================================");
    println!(" NyxShield: Confidential Settlement & Stealth Transfer Simulation");
    println!("================================================================================");

    let mut rng = OsRng;
    let generators = BulletproofGenerators::new(256);
    let bits = 32;

    println!("[1] Generating cryptographic identity keypairs for Alice and Bob...");
    let alice = StealthKeypair::generate(&mut rng);
    let bob = StealthKeypair::generate(&mut rng);

    println!("    Alice Public View: {}", hex::encode(&alice.meta_address.view_pubkey.compress().as_bytes()[..8]));
    println!("    Alice Public Spend: {}", hex::encode(&alice.meta_address.spend_pubkey.compress().as_bytes()[..8]));
    println!("    Bob Public View:   {}", hex::encode(&bob.meta_address.view_pubkey.compress().as_bytes()[..8]));
    println!("    Bob Public Spend:   {}", hex::encode(&bob.meta_address.spend_pubkey.compress().as_bytes()[..8]));

    println!("\n[2] Setting up Alice's UTXO vault with two confidential inputs...");
    let in_values = [500_000u64, 350_000u64]; // 850,000 total
    let in_blindings = [Scalar::random(&mut rng), Scalar::random(&mut rng)];
    let in_keys = [Scalar::random(&mut rng), Scalar::random(&mut rng)];

    println!("    Input 1: 500,000 sats (blinded)");
    println!("    Input 2: 350,000 sats (blinded)");
    println!("    Total Input: 850,000 sats");

    let transfer_to_bob = 620_000u64;
    let fee = 10_000u64;
    let expected_change = 850_000 - transfer_to_bob - fee; // 220,000

    println!("\n[3] Building Confidential Transaction with Bulletproofs Range Proofs...");
    println!("    Recipient (Bob): {} sats (amount hidden)", transfer_to_bob);
    println!("    Change (Alice):  {} sats (amount hidden)", expected_change);
    println!("    Miner Fee:       {} sats (public)", fee);

    let tx = ConfidentialTransaction::create(
        &generators,
        &in_values,
        &in_blindings,
        &in_keys,
        &[(bob.meta_address, transfer_to_bob)],
        &alice.meta_address,
        fee,
        bits,
        &mut rng,
    )
    .expect("Transaction creation must succeed");

    println!("\n[4] On-Chain Public View:");
    println!("    Inputs Count:  {}", tx.inputs.len());
    println!("    Outputs Count: {}", tx.outputs.len());
    println!("    Public Fee:    {} sats", tx.fee);
    println!("    Output 1 Commitment: {}", hex::encode(tx.outputs[0].commitment.compress().as_bytes()));
    println!("    Output 2 Commitment: {}", hex::encode(tx.outputs[1].commitment.compress().as_bytes()));

    println!("\n[5] Verifying Transaction Zero-Knowledge Proofs & Homomorphic Balance...");
    match tx.verify(&generators, bits) {
        Ok(_) => println!("    ✓ ALL ZERO-KNOWLEDGE RANGE PROOFS & BALANCE PROOF VERIFIED!"),
        Err(e) => println!("    ✗ Verification error: {}", e),
    }

    println!("\n[6] Bob scanning the blockchain using Private View Key...");
    let bob_detected = tx.outputs[0].recipient_stealth.scan_and_derive_spending_key(&bob);
    if let Some(key) = bob_detected {
        println!("    ✓ Bob identified Output 0 as his payment!");
        println!("    ✓ Derived one-time spending private key: {}", hex::encode(&key.as_bytes()[..8]));
    } else {
        println!("    ✗ Bob failed to detect payment");
    }

    println!("================================================================================");
}

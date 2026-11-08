use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use nyx_shield::{OneTimeStealthAddress, StealthKeypair};
use rand::rngs::OsRng;

#[test]
fn test_stealth_address_generation_and_scanning() {
    let mut rng = OsRng;

    // Alice generates a stealth keypair
    let alice = StealthKeypair::generate(&mut rng);

    // Bob generates an independent stealth keypair
    let bob = StealthKeypair::generate(&mut rng);

    // Charlie sends funds to Alice using Alice's public meta-address
    let one_time_addr = OneTimeStealthAddress::create(&alice.meta_address, &mut rng);

    // 1. Alice scans the blockchain and must detect that this payment belongs to her
    let recovered_key = one_time_addr.scan_and_derive_spending_key(&alice);
    assert!(recovered_key.is_some(), "Alice must successfully detect and scan her incoming payment");

    let spending_key = recovered_key.unwrap();
    // The derived private spending key must produce the exact one-time stealth public address on G
    assert_eq!(
        RISTRETTO_BASEPOINT_POINT * spending_key,
        one_time_addr.stealth_pubkey,
        "Spending key * G must match stealth destination address"
    );

    // 2. Bob scans the transaction and must NOT detect it as his
    let bob_scan = one_time_addr.scan_and_derive_spending_key(&bob);
    assert!(bob_scan.is_none(), "Unintended recipient Bob must not detect Alice's payment");
}

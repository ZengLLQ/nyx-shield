use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use nyx_shield::{BulletproofGenerators, ProofTranscript, RangeProof};
use rand::rngs::OsRng;

#[test]
fn test_range_proof_single_values() {
    let mut rng = OsRng;
    let generators = BulletproofGenerators::new(64);
    let bits = 32;

    let test_values = [0u64, 1u64, 42u64, 1000u64, (1u64 << 31) - 1, (1u64 << 32) - 1];

    for &val in &test_values {
        let blinding = Scalar::random(&mut rng);
        let mut prover_transcript = ProofTranscript::new(b"TestRangeProof");

        let (proof, commitment) = RangeProof::prove_single(
            &generators,
            &mut prover_transcript,
            &mut rng,
            val,
            &blinding,
            bits,
        )
        .expect("Proving valid range must succeed");

        let mut verifier_transcript = ProofTranscript::new(b"TestRangeProof");
        let verify_res = proof.verify_single(
            &generators,
            &mut verifier_transcript,
            &commitment,
            bits,
        );

        assert!(
            verify_res.is_ok(),
            "Verification failed for valid value {} with {} bits",
            val,
            bits
        );
    }
}

#[test]
fn test_range_proof_out_of_range_rejected() {
    let mut rng = OsRng;
    let generators = BulletproofGenerators::new(64);
    let bits = 16; // Valid range [0, 65535]

    let out_of_range_val = 65536u64; // 2^16
    let blinding = Scalar::random(&mut rng);
    let mut transcript = ProofTranscript::new(b"TestRangeProof");

    let res = RangeProof::prove_single(
        &generators,
        &mut transcript,
        &mut rng,
        out_of_range_val,
        &blinding,
        bits,
    );

    assert!(res.is_err(), "Value >= 2^16 must be rejected during range proof creation");
}

#[test]
fn test_range_proof_tampered_fails() {
    let mut rng = OsRng;
    let generators = BulletproofGenerators::new(64);
    let bits = 32;
    let val = 500u64;
    let blinding = Scalar::random(&mut rng);

    let mut p_trans = ProofTranscript::new(b"TestRangeProof");
    let (proof, commitment) = RangeProof::prove_single(
        &generators,
        &mut p_trans,
        &mut rng,
        val,
        &blinding,
        bits,
    )
    .unwrap();

    // 1. Tamper with t_hat
    let mut tampered_that = proof.clone();
    tampered_that.t_hat += Scalar::ONE;
    let mut v_trans1 = ProofTranscript::new(b"TestRangeProof");
    assert!(tampered_that.verify_single(&generators, &mut v_trans1, &commitment, bits).is_err());

    // 2. Tamper with tau_x
    let mut tampered_tau = proof.clone();
    tampered_tau.tau_x += Scalar::ONE;
    let mut v_trans2 = ProofTranscript::new(b"TestRangeProof");
    assert!(tampered_tau.verify_single(&generators, &mut v_trans2, &commitment, bits).is_err());

    // 3. Tamper with commitment point
    let wrong_comm = commitment + RISTRETTO_BASEPOINT_POINT;
    let mut v_trans3 = ProofTranscript::new(b"TestRangeProof");
    assert!(proof.verify_single(&generators, &mut v_trans3, &wrong_comm, bits).is_err());
}

#[test]
fn test_multi_range_proof_aggregation() {
    let mut rng = OsRng;
    let bits = 16;
    let values = [120u64, 450u64, 0u64, 3000u64];
    let m = values.len();
    let total_n = m * bits; // 64
    let generators = BulletproofGenerators::new(total_n);

    let blindings: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();

    let mut p_trans = ProofTranscript::new(b"TestMultiRangeProof");
    let (proof, commitments) = RangeProof::prove_multi(
        &generators,
        &mut p_trans,
        &mut rng,
        &values,
        &blindings,
        bits,
    )
    .expect("Multi-range proof creation should succeed");

    assert_eq!(commitments.len(), m);

    let mut v_trans = ProofTranscript::new(b"TestMultiRangeProof");
    let res = proof.verify_multi(&generators, &mut v_trans, &commitments, bits);
    assert!(res.is_ok(), "Aggregated multi-range proof verification must succeed");

    // Check that tampering one commitment fails whole aggregated batch
    let mut bad_commitments = commitments.clone();
    bad_commitments[1] += generators.g;
    let mut v_trans_bad = ProofTranscript::new(b"TestMultiRangeProof");
    assert!(proof.verify_multi(&generators, &mut v_trans_bad, &bad_commitments, bits).is_err());
}

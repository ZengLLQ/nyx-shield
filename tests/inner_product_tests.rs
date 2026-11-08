use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use nyx_shield::{
    inner_product_scalars, BulletproofGenerators, InnerProductProof, ProofError, ProofTranscript,
};
use rand::rngs::OsRng;

#[test]
fn test_inner_product_proof_roundtrip() {
    let mut rng = OsRng;
    let n_values = [2, 4, 8, 16, 32];
    let max_n = 32;
    let generators = BulletproofGenerators::new(max_n);

    for &n in &n_values {
        let (g_vec, h_vec) = generators.get_sub_generators(n).unwrap();

        let a_vec: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let b_vec: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let c = inner_product_scalars(&a_vec, &b_vec);

        // Commitment P = ⟨a, G⟩ + ⟨b, H⟩ + c * Q
        let mut scalars = Vec::with_capacity(2 * n + 1);
        let mut points = Vec::with_capacity(2 * n + 1);
        scalars.extend_from_slice(&a_vec);
        points.extend_from_slice(g_vec);
        scalars.extend_from_slice(&b_vec);
        points.extend_from_slice(h_vec);
        scalars.push(c);
        points.push(generators.q);
        let p = RistrettoPoint::multiscalar_mul(&scalars, &points);

        let mut prover_transcript = ProofTranscript::new(b"TestIPA");
        let proof = InnerProductProof::create(
            &mut prover_transcript,
            &generators.q,
            g_vec,
            h_vec,
            a_vec,
            b_vec,
        )
        .expect("IPA creation should succeed");

        assert_eq!(proof.l_vec.len(), n.trailing_zeros() as usize);
        assert_eq!(proof.r_vec.len(), n.trailing_zeros() as usize);

        let mut verifier_transcript = ProofTranscript::new(b"TestIPA");
        let result = proof.verify(
            &mut verifier_transcript,
            &generators.q,
            g_vec,
            h_vec,
            &p,
        );

        assert!(result.is_ok(), "Verification must succeed for valid IPA proof of size {}", n);
    }
}

#[test]
fn test_inner_product_tampering_fails() {
    let mut rng = OsRng;
    let n = 8;
    let generators = BulletproofGenerators::new(n);
    let (g_vec, h_vec) = generators.get_sub_generators(n).unwrap();

    let a_vec: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let b_vec: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let c = inner_product_scalars(&a_vec, &b_vec);

    let mut scalars = Vec::with_capacity(2 * n + 1);
    let mut points = Vec::with_capacity(2 * n + 1);
    scalars.extend_from_slice(&a_vec);
    points.extend_from_slice(g_vec);
    scalars.extend_from_slice(&b_vec);
    points.extend_from_slice(h_vec);
    scalars.push(c);
    points.push(generators.q);
    let p = RistrettoPoint::multiscalar_mul(&scalars, &points);

    let mut prover_transcript = ProofTranscript::new(b"TestIPA");
    let proof = InnerProductProof::create(
        &mut prover_transcript,
        &generators.q,
        g_vec,
        h_vec,
        a_vec,
        b_vec,
    )
    .unwrap();

    // 1. Tamper with scalar a
    let mut tampered_a = proof.clone();
    tampered_a.a += Scalar::ONE;
    let mut v_trans1 = ProofTranscript::new(b"TestIPA");
    assert!(tampered_a.verify(&mut v_trans1, &generators.q, g_vec, h_vec, &p).is_err());

    // 2. Tamper with scalar b
    let mut tampered_b = proof.clone();
    tampered_b.b += Scalar::ONE;
    let mut v_trans2 = ProofTranscript::new(b"TestIPA");
    assert!(tampered_b.verify(&mut v_trans2, &generators.q, g_vec, h_vec, &p).is_err());

    // 3. Tamper with L point
    let mut tampered_l = proof.clone();
    tampered_l.l_vec[0] += RISTRETTO_BASEPOINT_POINT;
    let mut v_trans3 = ProofTranscript::new(b"TestIPA");
    assert!(tampered_l.verify(&mut v_trans3, &generators.q, g_vec, h_vec, &p).is_err());

    // 4. Tamper with commitment point P
    let tampered_p = p + RISTRETTO_BASEPOINT_POINT;
    let mut v_trans4 = ProofTranscript::new(b"TestIPA");
    assert!(proof.verify(&mut v_trans4, &generators.q, g_vec, h_vec, &tampered_p).is_err());
}

#[test]
fn test_inner_product_non_power_of_two_fails() {
    let generators = BulletproofGenerators::new(16);
    let (g_vec, h_vec) = generators.get_sub_generators(6).unwrap();

    let a_vec = vec![Scalar::ONE; 6];
    let b_vec = vec![Scalar::ONE; 6];
    let mut transcript = ProofTranscript::new(b"TestIPA");

    let res = InnerProductProof::create(&mut transcript, &generators.q, g_vec, h_vec, a_vec, b_vec);
    assert_eq!(res, Err(ProofError::NonPowerOfTwo(6)));
}

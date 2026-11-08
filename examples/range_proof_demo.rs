use curve25519_dalek::scalar::Scalar;
use nyx_shield::{BulletproofGenerators, ProofTranscript, RangeProof};
use rand::rngs::OsRng;

fn main() {
    println!("================================================================================");
    println!(" NyxShield: Bulletproofs Range Proof & Multi-Value Aggregation Benchmark");
    println!("================================================================================");

    let mut rng = OsRng;
    let bits = 32;
    let generators = BulletproofGenerators::new(256);

    println!("[1] Benchmarking Single 32-bit Range Proof...");
    let val_single = 1_000_000u64;
    let blind_single = Scalar::random(&mut rng);

    let mut p_trans = ProofTranscript::new(b"NyxShield.RangeProof");
    let start_prove = std::time::Instant::now();
    let (single_proof, commitment) = RangeProof::prove_single(
        &generators,
        &mut p_trans,
        &mut rng,
        val_single,
        &blind_single,
        bits,
    )
    .unwrap();
    let prove_duration = start_prove.elapsed();

    let mut v_trans = ProofTranscript::new(b"NyxShield.RangeProof");
    let start_verify = std::time::Instant::now();
    let verify_res = single_proof.verify_single(&generators, &mut v_trans, &commitment, bits);
    let verify_duration = start_verify.elapsed();

    println!("    Value: {} (proven in [0, 2^32-1])", val_single);
    println!("    Prove Latency:  {:?}", prove_duration);
    println!("    Verify Latency: {:?}", verify_duration);
    println!("    Verify Result:  {:?}", verify_res);
    println!("    IPA Rounds:     {}", single_proof.ipp.l_vec.len());

    println!("\n[2] Benchmarking Aggregated Multi-Range Proof (m = 4 values)...");
    let multi_values = [25_000u64, 150_000u64, 999_999u64, 42u64];
    let multi_blindings = [
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    ];

    let mut p_trans_multi = ProofTranscript::new(b"NyxShield.RangeProof");
    let start_multi_prove = std::time::Instant::now();
    let (multi_proof, multi_commitments) = RangeProof::prove_multi(
        &generators,
        &mut p_trans_multi,
        &mut rng,
        &multi_values,
        &multi_blindings,
        bits,
    )
    .unwrap();
    let multi_prove_duration = start_multi_prove.elapsed();

    let mut v_trans_multi = ProofTranscript::new(b"NyxShield.RangeProof");
    let start_multi_verify = std::time::Instant::now();
    let multi_verify_res = multi_proof.verify_multi(
        &generators,
        &mut v_trans_multi,
        &multi_commitments,
        bits,
    );
    let multi_verify_duration = start_multi_verify.elapsed();

    println!("    Values: {:?}", multi_values);
    println!("    Aggregated Prove Latency:  {:?}", multi_prove_duration);
    println!("    Aggregated Verify Latency: {:?}", multi_verify_duration);
    println!("    Verify Result:             {:?}", multi_verify_res);
    println!("    IPA Rounds for 128 total bits: {}", multi_proof.ipp.l_vec.len());
    println!("    Notice: Aggregated proof grows only logarithmically with number of values!");
    println!("================================================================================");
}

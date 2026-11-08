use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::errors::ProofError;
use crate::generators::BulletproofGenerators;
use crate::inner_product::InnerProductProof;
use crate::pedersen::{inner_product_scalars, ValueCommitment};
use crate::transcript::ProofTranscript;

/// A non-interactive zero-knowledge Bulletproofs range proof.
/// Proves that committed values lie strictly within [0, 2^n - 1] without disclosing amounts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeProof {
    /// Commitment to bit vector A
    pub a: RistrettoPoint,
    /// Commitment to blinding vectors S
    pub s: RistrettoPoint,
    /// Commitment to t1 coefficient of t(X)
    pub t1: RistrettoPoint,
    /// Commitment to t2 coefficient of t(X)
    pub t2: RistrettoPoint,
    /// Evaluated polynomial t(x)
    pub t_hat: Scalar,
    /// Blinding scalar for t(x)
    pub tau_x: Scalar,
    /// Blinding scalar for inner-product generators
    pub mu: Scalar,
    /// Logarithmic Inner-Product Argument proof
    pub ipp: InnerProductProof,
}

impl RangeProof {
    /// Proves that a single secret value v lies in [0, 2^n - 1].
    pub fn prove_single<R: RngCore + CryptoRng>(
        generators: &BulletproofGenerators,
        transcript: &mut ProofTranscript,
        rng: &mut R,
        value: u64,
        blinding: &Scalar,
        bits: usize,
    ) -> Result<(Self, RistrettoPoint), ProofError> {
        let (proof, commitments) = Self::prove_multi(
            generators,
            transcript,
            rng,
            &[value],
            &[*blinding],
            bits,
        )?;
        Ok((proof, commitments[0]))
    }

    /// Verifies a single range proof for commitment V.
    pub fn verify_single(
        &self,
        generators: &BulletproofGenerators,
        transcript: &mut ProofTranscript,
        commitment: &RistrettoPoint,
        bits: usize,
    ) -> Result<(), ProofError> {
        Self::verify_multi(self, generators, transcript, &[*commitment], bits)
    }

    /// Proves that m values v_0, ..., v_{m-1} each lie in [0, 2^bits - 1] in an aggregated proof.
    pub fn prove_multi<R: RngCore + CryptoRng>(
        generators: &BulletproofGenerators,
        transcript: &mut ProofTranscript,
        rng: &mut R,
        values: &[u64],
        blindings: &[Scalar],
        bits: usize,
    ) -> Result<(Self, Vec<RistrettoPoint>), ProofError> {
        let m = values.len();
        if m == 0 {
            return Err(ProofError::LengthMismatch { expected: 1, actual: 0 });
        }
        if blindings.len() != m {
            return Err(ProofError::LengthMismatch { expected: m, actual: blindings.len() });
        }
        if ![8, 16, 32, 64].contains(&bits) {
            return Err(ProofError::InvalidBitLength(bits));
        }

        let total_n = m * bits;
        let (g_vec, h_vec) = generators.get_sub_generators(total_n)?;

        // Compute commitments V_j = v_j * G + γ_j * H
        let commitments: Vec<RistrettoPoint> = values
            .iter()
            .zip(blindings.iter())
            .map(|(&v, b)| ValueCommitment::commit(v, b, &generators.g, &generators.h))
            .collect();

        // 1. Bit-decomposition into a_L and a_R = a_L - 1
        let mut a_l = Vec::with_capacity(total_n);
        let mut a_r = Vec::with_capacity(total_n);

        for &val in values.iter() {
            // Value range check: must fit in `bits`
            if bits < 64 && val >= (1u64 << bits) {
                return Err(ProofError::RangeProofError(format!(
                    "Value {} exceeds range [0, 2^{}-1]", val, bits
                )));
            }
            for i in 0..bits {
                let bit = (val >> i) & 1;
                let bit_scalar = if bit == 1 { Scalar::ONE } else { Scalar::ZERO };
                a_l.push(bit_scalar);
                a_r.push(bit_scalar - Scalar::ONE);
            }
        }

        // 2. Sample blinding vectors s_L, s_R and scalars alpha, rho
        let mut s_l = Vec::with_capacity(total_n);
        let mut s_r = Vec::with_capacity(total_n);
        for _ in 0..total_n {
            s_l.push(Scalar::random(rng));
            s_r.push(Scalar::random(rng));
        }
        let alpha = Scalar::random(rng);
        let rho = Scalar::random(rng);

        // A = alpha * H + ⟨a_L, G⟩ + ⟨a_R, H_vec⟩
        let mut a_scalars = Vec::with_capacity(1 + 2 * total_n);
        let mut a_points = Vec::with_capacity(1 + 2 * total_n);
        a_scalars.push(alpha);
        a_points.push(generators.h);
        a_scalars.extend_from_slice(&a_l);
        a_points.extend_from_slice(g_vec);
        a_scalars.extend_from_slice(&a_r);
        a_points.extend_from_slice(h_vec);
        let a = RistrettoPoint::multiscalar_mul(&a_scalars, &a_points);

        // S = rho * H + ⟨s_L, G⟩ + ⟨s_R, H_vec⟩
        let mut s_scalars = Vec::with_capacity(1 + 2 * total_n);
        let mut s_points = Vec::with_capacity(1 + 2 * total_n);
        s_scalars.push(rho);
        s_points.push(generators.h);
        s_scalars.extend_from_slice(&s_l);
        s_points.extend_from_slice(g_vec);
        s_scalars.extend_from_slice(&s_r);
        s_points.extend_from_slice(h_vec);
        let s = RistrettoPoint::multiscalar_mul(&s_scalars, &s_points);

        // Append commitments to transcript
        transcript.append_message(b"dom-sep", b"NyxShield.RangeProof");
        transcript.append_u64(b"n", bits as u64);
        transcript.append_u64(b"m", m as u64);
        for v_point in commitments.iter() {
            transcript.append_point(b"V", v_point);
        }
        transcript.append_point(b"A", &a);
        transcript.append_point(b"S", &s);

        // 3. Challenge scalars y, z
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        let z_sq = z * z;

        // Compute y^i and 2^i powers
        let mut y_powers = Vec::with_capacity(total_n);
        let mut y_inv_powers = Vec::with_capacity(total_n);
        let y_inv = y.invert();
        let mut cur_y = Scalar::ONE;
        let mut cur_y_inv = Scalar::ONE;
        for _ in 0..total_n {
            y_powers.push(cur_y);
            y_inv_powers.push(cur_y_inv);
            cur_y *= y;
            cur_y_inv *= y_inv;
        }

        let mut two_powers = Vec::with_capacity(bits);
        let mut cur_two = Scalar::ONE;
        let scalar_two = Scalar::from(2u64);
        for _ in 0..bits {
            two_powers.push(cur_two);
            cur_two *= scalar_two;
        }

        // Construct l(X) = (a_L - z * 1) + s_L * X = l0 + l1 * X
        let mut l0 = Vec::with_capacity(total_n);
        let l1 = s_l.clone();
        for val in a_l.iter() {
            l0.push(val - z);
        }

        // Construct r(X) = y^i * (a_R + z * 1 + s_R * X) + ∑ z^(j+2) * 2^i
        let mut r0 = Vec::with_capacity(total_n);
        let mut r1 = Vec::with_capacity(total_n);

        let mut cur_z_power = z_sq; // z^2 for j=0
        for j in 0..m {
            for i in 0..bits {
                let idx = j * bits + i;
                let z_two_term = cur_z_power * two_powers[i];
                let r0_val = y_powers[idx] * (a_r[idx] + z) + z_two_term;
                let r1_val = y_powers[idx] * s_r[idx];
                r0.push(r0_val);
                r1.push(r1_val);
            }
            cur_z_power *= z;
        }

        // t(X) = ⟨l(X), r(X)⟩ = t0 + t1 * X + t2 * X^2
        let t1 = inner_product_scalars(&l1, &r0) + inner_product_scalars(&l0, &r1);
        let t2 = inner_product_scalars(&l1, &r1);

        let tau1 = Scalar::random(rng);
        let tau2 = Scalar::random(rng);

        let t1_point = ValueCommitment::commit(0, &tau1, &generators.g, &generators.h)
            + generators.g * t1;
        let t2_point = ValueCommitment::commit(0, &tau2, &generators.g, &generators.h)
            + generators.g * t2;

        transcript.append_point(b"T1", &t1_point);
        transcript.append_point(b"T2", &t2_point);

        // 4. Challenge scalar x
        let x = transcript.challenge_scalar(b"x");
        let x_sq = x * x;

        // Evaluate polynomials at x
        let mut l = Vec::with_capacity(total_n);
        let mut r = Vec::with_capacity(total_n);
        for i in 0..total_n {
            l.push(l0[i] + l1[i] * x);
            r.push(r0[i] + r1[i] * x);
        }

        let t_hat = inner_product_scalars(&l, &r);

        // Compute tau_x = tau2 * x^2 + tau1 * x + ∑ z^(j+2) * γ_j
        let mut tau_x = tau2 * x_sq + tau1 * x;
        let mut z_pow = z_sq;
        for &b in blindings.iter() {
            tau_x += z_pow * b;
            z_pow *= z;
        }

        let mu = alpha + rho * x;

        transcript.append_scalar(b"t_hat", &t_hat);
        transcript.append_scalar(b"tau_x", &tau_x);
        transcript.append_scalar(b"mu", &mu);

        // 5. Challenge w for inner-product argument
        let w = transcript.challenge_scalar(b"w");
        let q_prime = generators.q * w;

        // Generator scaling for H': H'_i = y^(-i) * H_i
        let mut h_prime = Vec::with_capacity(total_n);
        for i in 0..total_n {
            h_prime.push(h_vec[i] * y_inv_powers[i]);
        }

        let ipp = InnerProductProof::create(
            transcript,
            &q_prime,
            g_vec,
            &h_prime,
            l,
            r,
        )?;

        let proof = RangeProof {
            a,
            s,
            t1: t1_point,
            t2: t2_point,
            t_hat,
            tau_x,
            mu,
            ipp,
        };

        Ok((proof, commitments))
    }

    /// Verifies an aggregated Bulletproofs range proof across commitments V_0, ..., V_{m-1}.
    pub fn verify_multi(
        &self,
        generators: &BulletproofGenerators,
        transcript: &mut ProofTranscript,
        commitments: &[RistrettoPoint],
        bits: usize,
    ) -> Result<(), ProofError> {
        let m = commitments.len();
        if m == 0 {
            return Err(ProofError::LengthMismatch { expected: 1, actual: 0 });
        }
        if ![8, 16, 32, 64].contains(&bits) {
            return Err(ProofError::InvalidBitLength(bits));
        }

        let total_n = m * bits;
        let (g_vec, h_vec) = generators.get_sub_generators(total_n)?;

        transcript.append_message(b"dom-sep", b"NyxShield.RangeProof");
        transcript.append_u64(b"n", bits as u64);
        transcript.append_u64(b"m", m as u64);
        for v_point in commitments.iter() {
            transcript.append_point(b"V", v_point);
        }
        transcript.append_point(b"A", &self.a);
        transcript.append_point(b"S", &self.s);

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        let z_sq = z * z;

        transcript.append_point(b"T1", &self.t1);
        transcript.append_point(b"T2", &self.t2);

        let x = transcript.challenge_scalar(b"x");
        let x_sq = x * x;

        transcript.append_scalar(b"t_hat", &self.t_hat);
        transcript.append_scalar(b"tau_x", &self.tau_x);
        transcript.append_scalar(b"mu", &self.mu);

        let w = transcript.challenge_scalar(b"w");
        let q_prime = generators.q * w;

        // Compute delta(y, z)
        // delta(y, z) = (z - z^2) ⟨1, y^n⟩ - ∑_{j=0}^{m-1} z^(j+3) ⟨1, 2^n⟩
        let mut y_powers = Vec::with_capacity(total_n);
        let mut y_inv_powers = Vec::with_capacity(total_n);
        let y_inv = y.invert();
        let mut cur_y = Scalar::ONE;
        let mut cur_y_inv = Scalar::ONE;
        for _ in 0..total_n {
            y_powers.push(cur_y);
            y_inv_powers.push(cur_y_inv);
            cur_y *= y;
            cur_y_inv *= y_inv;
        }

        let sum_y = y_powers.iter().fold(Scalar::ZERO, |acc, &val| acc + val);

        let mut two_powers = Vec::with_capacity(bits);
        let mut cur_two = Scalar::ONE;
        let scalar_two = Scalar::from(2u64);
        for _ in 0..bits {
            two_powers.push(cur_two);
            cur_two *= scalar_two;
        }
        let sum_two = two_powers.iter().fold(Scalar::ZERO, |acc, &val| acc + val);

        let mut delta = (z - z_sq) * sum_y;
        let mut z_pow = z_sq * z; // z^3
        for _ in 0..m {
            delta -= z_pow * sum_two;
            z_pow *= z;
        }

        // Equation 1: Check t_hat commitment consistency
        // t_hat * G + tau_x * H == delta * G + x * T1 + x^2 * T2 + ∑ z^(j+2) * V_j
        let mut t_scalars = Vec::with_capacity(4 + m);
        let mut t_points = Vec::with_capacity(4 + m);

        t_scalars.push(-self.t_hat + delta);
        t_points.push(generators.g);

        t_scalars.push(-self.tau_x);
        t_points.push(generators.h);

        t_scalars.push(x);
        t_points.push(self.t1);

        t_scalars.push(x_sq);
        t_points.push(self.t2);

        let mut z_term = z_sq;
        for v_point in commitments.iter() {
            t_scalars.push(z_term);
            t_points.push(*v_point);
            z_term *= z;
        }

        let check_t = RistrettoPoint::multiscalar_mul(&t_scalars, &t_points);
        if check_t != RistrettoPoint::default() {
            return Err(ProofError::VerificationFailed(
                "Range proof polynomial t(X) consistency check failed".into(),
            ));
        }

        // Equation 2: Inner-product commitment point P verification
        // P = A + x * S - z * ∑ G_i + ∑ (z * y^i + z^(j+2) * 2^i) * H'_i - mu * H + (w * t_hat) * Q
        let mut h_prime = Vec::with_capacity(total_n);
        for i in 0..total_n {
            h_prime.push(h_vec[i] * y_inv_powers[i]);
        }

        let mut p_scalars = Vec::with_capacity(3 + 2 * total_n + 1);
        let mut p_points = Vec::with_capacity(3 + 2 * total_n + 1);

        p_scalars.push(Scalar::ONE);
        p_points.push(self.a);

        p_scalars.push(x);
        p_points.push(self.s);

        p_scalars.push(-self.mu);
        p_points.push(generators.h);

        for i in 0..total_n {
            p_scalars.push(-z);
            p_points.push(g_vec[i]);
        }

        let mut z_power_j = z_sq;
        for j in 0..m {
            for i in 0..bits {
                let idx = j * bits + i;
                let coeff = z * y_powers[idx] + z_power_j * two_powers[i];
                p_scalars.push(coeff);
                p_points.push(h_prime[idx]);
            }
            z_power_j *= z;
        }

        let p_without_q = RistrettoPoint::multiscalar_mul(&p_scalars, &p_points);
        let p_final = p_without_q + q_prime * self.t_hat;

        self.ipp.verify(
            transcript,
            &q_prime,
            g_vec,
            &h_prime,
            &p_final,
        )
    }
}

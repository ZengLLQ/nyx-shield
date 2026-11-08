use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use serde::{Deserialize, Serialize};

use crate::errors::ProofError;
use crate::pedersen::inner_product_scalars;
use crate::transcript::ProofTranscript;

/// Inner-Product Argument proof asserting that c = ⟨a, b⟩ for committed vectors a, b.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerProductProof {
    pub l_vec: Vec<RistrettoPoint>,
    pub r_vec: Vec<RistrettoPoint>,
    pub a: Scalar,
    pub b: Scalar,
}

impl InnerProductProof {
    /// Creates an inner-product argument proof in O(log n) rounds.
    pub fn create(
        transcript: &mut ProofTranscript,
        q: &RistrettoPoint,
        g_vec: &[RistrettoPoint],
        h_vec: &[RistrettoPoint],
        mut a_vec: Vec<Scalar>,
        mut b_vec: Vec<Scalar>,
    ) -> Result<Self, ProofError> {
        let mut n = a_vec.len();
        if n == 0 || (n & (n - 1)) != 0 {
            return Err(ProofError::NonPowerOfTwo(n));
        }
        if b_vec.len() != n || g_vec.len() != n || h_vec.len() != n {
            return Err(ProofError::LengthMismatch {
                expected: n,
                actual: b_vec.len(),
            });
        }

        let mut g = g_vec.to_vec();
        let mut h = h_vec.to_vec();

        let num_rounds = n.trailing_zeros() as usize;
        let mut l_vec = Vec::with_capacity(num_rounds);
        let mut r_vec = Vec::with_capacity(num_rounds);

        while n > 1 {
            let n_half = n / 2;

            let a_lo = &a_vec[..n_half];
            let a_hi = &a_vec[n_half..];
            let b_lo = &b_vec[..n_half];
            let b_hi = &b_vec[n_half..];

            let g_lo = &g[..n_half];
            let g_hi = &g[n_half..];
            let h_lo = &h[..n_half];
            let h_hi = &h[n_half..];

            let c_l = inner_product_scalars(a_lo, b_hi);
            let c_r = inner_product_scalars(a_hi, b_lo);

            // L = ⟨a_lo, G_hi⟩ + ⟨b_hi, H_lo⟩ + c_l * Q
            let l_scalars: Vec<Scalar> = a_lo.iter().chain(b_hi.iter()).cloned().chain(std::iter::once(c_l)).collect();
            let l_points: Vec<RistrettoPoint> = g_hi.iter().chain(h_lo.iter()).cloned().chain(std::iter::once(*q)).collect();
            let l_point = RistrettoPoint::multiscalar_mul(&l_scalars, &l_points);

            // R = ⟨a_hi, G_lo⟩ + ⟨b_lo, H_hi⟩ + c_r * Q
            let r_scalars: Vec<Scalar> = a_hi.iter().chain(b_lo.iter()).cloned().chain(std::iter::once(c_r)).collect();
            let r_points: Vec<RistrettoPoint> = g_lo.iter().chain(h_hi.iter()).cloned().chain(std::iter::once(*q)).collect();
            let r_point = RistrettoPoint::multiscalar_mul(&r_scalars, &r_points);

            transcript.append_point(b"L", &l_point);
            transcript.append_point(b"R", &r_point);

            let u = transcript.challenge_scalar(b"u");
            let u_inv = u.invert();

            // Fold vectors a and b
            let mut a_next = Vec::with_capacity(n_half);
            let mut b_next = Vec::with_capacity(n_half);
            for i in 0..n_half {
                a_next.push(a_lo[i] * u + a_hi[i] * u_inv);
                b_next.push(b_lo[i] * u_inv + b_hi[i] * u);
            }
            a_vec = a_next;
            b_vec = b_next;

            // Fold generators G and H
            let mut g_next = Vec::with_capacity(n_half);
            let mut h_next = Vec::with_capacity(n_half);
            for i in 0..n_half {
                g_next.push(RistrettoPoint::multiscalar_mul(&[u_inv, u], &[g_lo[i], g_hi[i]]));
                h_next.push(RistrettoPoint::multiscalar_mul(&[u, u_inv], &[h_lo[i], h_hi[i]]));
            }
            g = g_next;
            h = h_next;

            l_vec.push(l_point);
            r_vec.push(r_point);
            n = n_half;
        }

        Ok(Self {
            l_vec,
            r_vec,
            a: a_vec[0],
            b: b_vec[0],
        })
    }

    /// Verifies the inner-product argument proof against commitment point P.
    pub fn verify(
        &self,
        transcript: &mut ProofTranscript,
        q: &RistrettoPoint,
        g_vec: &[RistrettoPoint],
        h_vec: &[RistrettoPoint],
        p: &RistrettoPoint,
    ) -> Result<(), ProofError> {
        let n = g_vec.len();
        if n == 0 || (n & (n - 1)) != 0 {
            return Err(ProofError::NonPowerOfTwo(n));
        }
        let num_rounds = n.trailing_zeros() as usize;
        if self.l_vec.len() != num_rounds || self.r_vec.len() != num_rounds {
            return Err(ProofError::LengthMismatch {
                expected: num_rounds,
                actual: self.l_vec.len(),
            });
        }

        // Recover challenge scalars from transcript
        let mut challenges = Vec::with_capacity(num_rounds);
        let mut challenges_inv = Vec::with_capacity(num_rounds);
        for (l_pt, r_pt) in self.l_vec.iter().zip(self.r_vec.iter()) {
            transcript.append_point(b"L", l_pt);
            transcript.append_point(b"R", r_pt);
            let u = transcript.challenge_scalar(b"u");
            challenges.push(u);
            challenges_inv.push(u.invert());
        }

        // Compute basis expansion coefficients s_i
        // s_i = ∏ (u_j if bit_j == 1 else u_j^-1)
        let mut s_vec = Vec::with_capacity(n);
        for i in 0..n {
            let mut s = Scalar::ONE;
            for j in 0..num_rounds {
                let bit = (i >> (num_rounds - 1 - j)) & 1;
                if bit == 1 {
                    s *= challenges[j];
                } else {
                    s *= challenges_inv[j];
                }
            }
            s_vec.push(s);
        }

        // Single multi-scalar multiplication verification equation:
        // P + ∑ (u_j^2 L_j + u_j^-2 R_j) - ∑ (a * s_i) G_i - ∑ (b * s_i^-1) H_i - (a * b) Q == 0
        let mut scalars = Vec::with_capacity(1 + 2 * num_rounds + 2 * n + 1);
        let mut points = Vec::with_capacity(1 + 2 * num_rounds + 2 * n + 1);

        scalars.push(Scalar::ONE);
        points.push(*p);

        for j in 0..num_rounds {
            let u_sq = challenges[j] * challenges[j];
            let u_inv_sq = challenges_inv[j] * challenges_inv[j];
            scalars.push(u_sq);
            points.push(self.l_vec[j]);
            scalars.push(u_inv_sq);
            points.push(self.r_vec[j]);
        }

        for i in 0..n {
            scalars.push(-self.a * s_vec[i]);
            points.push(g_vec[i]);

            let s_inv = s_vec[i].invert();
            scalars.push(-self.b * s_inv);
            points.push(h_vec[i]);
        }

        scalars.push(-(self.a * self.b));
        points.push(*q);

        let check_point = RistrettoPoint::multiscalar_mul(&scalars, &points);
        if check_point == RistrettoPoint::default() {
            Ok(())
        } else {
            Err(ProofError::VerificationFailed(
                "Inner-product argument MSM check failed".into(),
            ))
        }
    }
}

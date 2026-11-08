use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::{Digest, Sha512};
use crate::errors::ProofError;

/// Cryptographic generator suite for Pedersen commitments and Bulletproofs vector inner products.
#[derive(Clone, Debug)]
pub struct BulletproofGenerators {
    /// Primary value basepoint G (canonical Ristretto255 basepoint)
    pub g: RistrettoPoint,
    /// Primary blinding basepoint H (orthogonal generator)
    pub h: RistrettoPoint,
    /// Auxiliary generator Q for the Inner-Product Argument
    pub q: RistrettoPoint,
    /// Vector generators G_i
    pub g_vec: Vec<RistrettoPoint>,
    /// Vector generators H_i
    pub h_vec: Vec<RistrettoPoint>,
}

impl BulletproofGenerators {
    /// Derives generators up to capacity `capacity` deterministically.
    pub fn new(capacity: usize) -> Self {
        let g = RISTRETTO_BASEPOINT_POINT;

        // Derive H via transparent hash-to-group
        let mut hasher_h = Sha512::new();
        hasher_h.update(b"NyxShield.Generators.BasepointH");
        let hash_h = hasher_h.finalize();
        let mut h_bytes = [0u8; 64];
        h_bytes.copy_from_slice(&hash_h);
        let h = RistrettoPoint::from_uniform_bytes(&h_bytes);

        // Derive Q via transparent hash-to-group
        let mut hasher_q = Sha512::new();
        hasher_q.update(b"NyxShield.Generators.BasepointQ");
        let hash_q = hasher_q.finalize();
        let mut q_bytes = [0u8; 64];
        q_bytes.copy_from_slice(&hash_q);
        let q = RistrettoPoint::from_uniform_bytes(&q_bytes);

        let mut g_vec = Vec::with_capacity(capacity);
        let mut h_vec = Vec::with_capacity(capacity);

        for i in 0..capacity {
            let mut hasher_gi = Sha512::new();
            hasher_gi.update(b"NyxShield.VectorGen.G:");
            hasher_gi.update(&(i as u64).to_le_bytes());
            let hash_gi = hasher_gi.finalize();
            let mut gi_bytes = [0u8; 64];
            gi_bytes.copy_from_slice(&hash_gi);
            g_vec.push(RistrettoPoint::from_uniform_bytes(&gi_bytes));

            let mut hasher_hi = Sha512::new();
            hasher_hi.update(b"NyxShield.VectorGen.H:");
            hasher_hi.update(&(i as u64).to_le_bytes());
            let hash_hi = hasher_hi.finalize();
            let mut hi_bytes = [0u8; 64];
            hi_bytes.copy_from_slice(&hash_hi);
            h_vec.push(RistrettoPoint::from_uniform_bytes(&hi_bytes));
        }

        Self {
            g,
            h,
            q,
            g_vec,
            h_vec,
        }
    }

    /// Returns a sub-slice of vector generators for proofs of size `n`.
    pub fn get_sub_generators(&self, n: usize) -> Result<(&[RistrettoPoint], &[RistrettoPoint]), ProofError> {
        if n > self.g_vec.len() {
            return Err(ProofError::GeneratorCapacityExceeded {
                required: n,
                available: self.g_vec.len(),
            });
        }
        Ok((&self.g_vec[..n], &self.h_vec[..n]))
    }
}

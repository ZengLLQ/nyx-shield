use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand_core::{CryptoRng, RngCore};
use std::ops::{Add, Sub};

/// A Pedersen commitment to a 64-bit value with a secret blinding factor:
///     C = v * G + γ * H
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueCommitment {
    pub value: u64,
    pub blinding: Scalar,
    pub point: RistrettoPoint,
}

impl ValueCommitment {
    /// Computes pure commitment point C = v * G + blinding * H.
    pub fn commit(value: u64, blinding: &Scalar, g: &RistrettoPoint, h: &RistrettoPoint) -> RistrettoPoint {
        let v_scalar = Scalar::from(value);
        RistrettoPoint::multiscalar_mul(&[v_scalar, *blinding], &[*g, *h])
    }

    /// Constructs a new commitment container.
    pub fn new(value: u64, blinding: Scalar, g: &RistrettoPoint, h: &RistrettoPoint) -> Self {
        let point = Self::commit(value, &blinding, g, h);
        Self {
            value,
            blinding,
            point,
        }
    }

    /// Generates a new commitment with a cryptographically secure random blinding factor.
    pub fn new_random<R: RngCore + CryptoRng>(
        value: u64,
        rng: &mut R,
        g: &RistrettoPoint,
        h: &RistrettoPoint,
    ) -> Self {
        let blinding = Scalar::random(rng);
        Self::new(value, blinding, g, h)
    }

    /// Verifies if a given point matches a claimed value and blinding factor.
    pub fn verify(&self, g: &RistrettoPoint, h: &RistrettoPoint) -> bool {
        self.point == Self::commit(self.value, &self.blinding, g, h)
    }
}

impl Add for ValueCommitment {
    type Output = Self;

    /// Homomorphic addition: (v1 + v2) * G + (γ1 + γ2) * H
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value.saturating_add(rhs.value),
            blinding: self.blinding + rhs.blinding,
            point: self.point + rhs.point,
        }
    }
}

impl Sub for ValueCommitment {
    type Output = Self;

    /// Homomorphic subtraction: (v1 - v2) * G + (γ1 - γ2) * H
    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value.saturating_sub(rhs.value),
            blinding: self.blinding - rhs.blinding,
            point: self.point - rhs.point,
        }
    }
}

/// Evaluates the inner product of two scalar vectors: ⟨a, b⟩ = ∑ (a_i * b_i).
pub fn inner_product_scalars(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), b.len(), "Vectors must have identical length");
    let mut sum = Scalar::ZERO;
    for (x, y) in a.iter().zip(b.iter()) {
        sum += x * y;
    }
    sum
}

/// Multi-scalar multiplication computing: ∑ (scalars[i] * points[i]).
pub fn multiscalar_mul(scalars: &[Scalar], points: &[RistrettoPoint]) -> RistrettoPoint {
    assert_eq!(scalars.len(), points.len(), "Length mismatch in multiscalar mul");
    RistrettoPoint::multiscalar_mul(scalars, points)
}

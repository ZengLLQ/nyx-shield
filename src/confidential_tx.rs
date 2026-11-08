use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::errors::ProofError;
use crate::generators::BulletproofGenerators;
use crate::range_proof::RangeProof;
use crate::stealth::{OneTimeStealthAddress, StealthMetaAddress};
use crate::transcript::ProofTranscript;

/// Schnorr signature proving knowledge of a discrete logarithm over a chosen basepoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrSignature {
    pub r_point: RistrettoPoint,
    pub s_scalar: Scalar,
}

impl SchnorrSignature {
    /// Signs a message hash with private key `secret` relative to basepoint `base`.
    pub fn sign<R: RngCore + CryptoRng>(
        secret: &Scalar,
        base: &RistrettoPoint,
        message: &[u8],
        rng: &mut R,
    ) -> Self {
        let k = Scalar::random(rng);
        let r_point = *base * k;

        let mut hasher = Sha512::new();
        hasher.update(b"NyxShield.SchnorrSignature:");
        hasher.update(base.compress().as_bytes());
        hasher.update(r_point.compress().as_bytes());
        hasher.update(message);
        let hash = hasher.finalize();

        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash);
        let e = Scalar::from_bytes_mod_order_wide(&wide);

        let s_scalar = k + e * secret;

        Self { r_point, s_scalar }
    }

    /// Verifies Schnorr signature against public key point `pubkey` relative to basepoint `base`.
    pub fn verify(
        &self,
        pubkey: &RistrettoPoint,
        base: &RistrettoPoint,
        message: &[u8],
    ) -> bool {
        let mut hasher = Sha512::new();
        hasher.update(b"NyxShield.SchnorrSignature:");
        hasher.update(base.compress().as_bytes());
        hasher.update(self.r_point.compress().as_bytes());
        hasher.update(message);
        let hash = hasher.finalize();

        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash);
        let e = Scalar::from_bytes_mod_order_wide(&wide);

        // Check: s * base == R + e * pubkey
        let lhs = *base * self.s_scalar;
        let rhs = self.r_point + *pubkey * e;

        lhs == rhs
    }
}

/// A confidential transaction input referencing an existing UTXO.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInput {
    pub stealth_address: RistrettoPoint,
    pub commitment: RistrettoPoint,
    pub ownership_signature: SchnorrSignature,
}

/// A confidential transaction output creating a new blinded UTXO with range proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    pub recipient_stealth: OneTimeStealthAddress,
    pub commitment: RistrettoPoint,
    pub range_proof: RangeProof,
}

/// A complete zero-knowledge confidential transaction with hidden amounts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTransaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub fee: u64,
    /// Balance proof: Schnorr signature proving ΔC = (∑γ_in - ∑γ_out) * H
    pub balance_signature: SchnorrSignature,
}

impl ConfidentialTransaction {
    /// Builds and signs a confidential transaction transferring funds to recipients.
    pub fn create<R: RngCore + CryptoRng>(
        generators: &BulletproofGenerators,
        input_values: &[u64],
        input_blindings: &[Scalar],
        input_keys: &[Scalar], // Spending keys x such that x * G == input.stealth_address
        recipients: &[(StealthMetaAddress, u64)],
        change_recipient: &StealthMetaAddress,
        fee: u64,
        bits: usize,
        rng: &mut R,
    ) -> Result<Self, ProofError> {
        let n_in = input_values.len();
        if n_in == 0 || input_blindings.len() != n_in || input_keys.len() != n_in {
            return Err(ProofError::LengthMismatch { expected: n_in, actual: input_blindings.len() });
        }

        let total_input: u64 = input_values.iter().sum();
        let total_recipient_amount: u64 = recipients.iter().map(|(_, a)| *a).sum();
        let total_required = total_recipient_amount.checked_add(fee).ok_or(ProofError::BalanceMismatch)?;

        if total_input < total_required {
            return Err(ProofError::BalanceMismatch);
        }

        let change_amount = total_input - total_required;

        // Build inputs and ownership signatures
        let mut inputs = Vec::with_capacity(n_in);
        for i in 0..n_in {
            let val = input_values[i];
            let blind = input_blindings[i];
            let key = input_keys[i];

            let comm = generators.g * Scalar::from(val) + generators.h * blind;
            let stealth_pubkey = RISTRETTO_BASEPOINT_POINT * key;

            // Ownership signature over commitment using private spending key on G
            let sig = SchnorrSignature::sign(&key, &RISTRETTO_BASEPOINT_POINT, comm.compress().as_bytes(), rng);

            inputs.push(TxInput {
                stealth_address: stealth_pubkey,
                commitment: comm,
                ownership_signature: sig,
            });
        }

        // Build outputs
        let mut output_specs = Vec::with_capacity(recipients.len() + 1);
        for &(recip, amt) in recipients.iter() {
            output_specs.push((recip, amt));
        }
        if change_amount > 0 || recipients.is_empty() {
            output_specs.push((*change_recipient, change_amount));
        }

        let mut outputs = Vec::with_capacity(output_specs.len());
        let mut out_blindings = Vec::with_capacity(output_specs.len());

        for &(recip, amt) in output_specs.iter() {
            let stealth = OneTimeStealthAddress::create(&recip, rng);
            let blinding = Scalar::random(rng);
            let comm = generators.g * Scalar::from(amt) + generators.h * blinding;

            let mut rp_transcript = ProofTranscript::new(b"NyxShield.RangeProof");
            let (proof, _) = RangeProof::prove_single(
                generators,
                &mut rp_transcript,
                rng,
                amt,
                &blinding,
                bits,
            )?;

            out_blindings.push(blinding);
            outputs.push(TxOutput {
                recipient_stealth: stealth,
                commitment: comm,
                range_proof: proof,
            });
        }

        // Compute excess blinding factor: Δγ = ∑γ_in - ∑γ_out
        let sum_in_blind: Scalar = input_blindings.iter().copied().fold(Scalar::ZERO, |acc, b| acc + b);
        let sum_out_blind: Scalar = out_blindings.iter().copied().fold(Scalar::ZERO, |acc, b| acc + b);
        let excess_blind = sum_in_blind - sum_out_blind;

        // Transaction hash message for balance signature
        let tx_hash = compute_tx_digest(&inputs, &outputs, fee);

        // Balance signature under excess blinding factor relative to basepoint H
        let balance_sig = SchnorrSignature::sign(&excess_blind, &generators.h, &tx_hash, rng);

        Ok(Self {
            inputs,
            outputs,
            fee,
            balance_signature: balance_sig,
        })
    }

    /// Verifies all zero-knowledge range proofs, ownership signatures, and homomorphic balance.
    pub fn verify(&self, generators: &BulletproofGenerators, bits: usize) -> Result<(), ProofError> {
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return Err(ProofError::FormatError("Transaction has empty inputs or outputs".into()));
        }

        // 1. Verify input ownership signatures
        for inp in self.inputs.iter() {
            let msg = inp.commitment.compress().as_bytes().to_vec();
            if !inp.ownership_signature.verify(&inp.stealth_address, &RISTRETTO_BASEPOINT_POINT, &msg) {
                return Err(ProofError::SignatureError("Invalid input ownership signature".into()));
            }
        }

        // 2. Verify all output zero-knowledge range proofs
        for out in self.outputs.iter() {
            let mut rp_transcript = ProofTranscript::new(b"NyxShield.RangeProof");
            out.range_proof.verify_single(
                generators,
                &mut rp_transcript,
                &out.commitment,
                bits,
            )?;
        }

        // 3. Verify homomorphic value conservation:
        // ΔC = ∑ C_in - ∑ C_out - Fee * G == Δγ * H
        let mut sum_in = RistrettoPoint::default();
        for inp in self.inputs.iter() {
            sum_in += inp.commitment;
        }

        let mut sum_out = RistrettoPoint::default();
        for out in self.outputs.iter() {
            sum_out += out.commitment;
        }

        let fee_point = generators.g * Scalar::from(self.fee);
        let delta_c = sum_in - sum_out - fee_point;

        // Verify balance Schnorr signature on H
        let tx_hash = compute_tx_digest(&self.inputs, &self.outputs, self.fee);
        if !self.balance_signature.verify(&delta_c, &generators.h, &tx_hash) {
            return Err(ProofError::BalanceMismatch);
        }

        Ok(())
    }
}

/// Computes canonical SHA-512 digest of transaction structure.
fn compute_tx_digest(inputs: &[TxInput], outputs: &[TxOutput], fee: u64) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(b"NyxShield.ConfidentialTx.Digest:");
    hasher.update(&(inputs.len() as u64).to_le_bytes());
    for inp in inputs {
        hasher.update(inp.stealth_address.compress().as_bytes());
        hasher.update(inp.commitment.compress().as_bytes());
    }
    hasher.update(&(outputs.len() as u64).to_le_bytes());
    for out in outputs {
        hasher.update(out.recipient_stealth.stealth_pubkey.compress().as_bytes());
        hasher.update(out.commitment.compress().as_bytes());
    }
    hasher.update(&fee.to_le_bytes());

    let hash = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&hash);
    output
}

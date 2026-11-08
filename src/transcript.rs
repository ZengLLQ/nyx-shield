use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// Domain-separated Fiat-Shamir transcript for non-interactive zero-knowledge proofs.
#[derive(Clone, Debug)]
pub struct ProofTranscript {
    state: Sha512,
}

impl ProofTranscript {
    /// Initializes a new transcript with a domain-separation label.
    pub fn new(label: &'static [u8]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(b"NyxShield.Transcript.Init:");
        hasher.update((label.len() as u64).to_le_bytes());
        hasher.update(label);
        Self { state: hasher }
    }

    /// Appends arbitrary byte message with a domain label.
    pub fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        self.state.update(b"NyxShield.Item:");
        self.state.update(label);
        self.state.update((message.len() as u64).to_le_bytes());
        self.state.update(message);
    }

    /// Appends a 64-bit unsigned integer to the transcript.
    pub fn append_u64(&mut self, label: &'static [u8], value: u64) {
        self.append_message(label, &value.to_le_bytes());
    }

    /// Appends an elliptic curve group element (Ristretto point).
    pub fn append_point(&mut self, label: &'static [u8], point: &RistrettoPoint) {
        let compressed = point.compress();
        self.append_message(label, compressed.as_bytes());
    }

    /// Appends a compressed Ristretto point.
    pub fn append_compressed_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.append_message(label, point.as_bytes());
    }

    /// Appends a field scalar to the transcript.
    pub fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    /// Generates a cryptographic challenge scalar reduced modulo group order.
    pub fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut challenge_hasher = self.state.clone();
        challenge_hasher.update(b"NyxShield.Challenge:");
        challenge_hasher.update(label);

        let hash_output = challenge_hasher.finalize();
        let mut wide_bytes = [0u8; 64];
        wide_bytes.copy_from_slice(&hash_output);

        // Update ongoing state with the challenge to prevent replay
        self.state.update(b"NyxShield.ChallOutput:");
        self.state.update(&hash_output);

        Scalar::from_bytes_mod_order_wide(&wide_bytes)
    }
}

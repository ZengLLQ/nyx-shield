//! # NyxShield
//!
//! High-performance Zero-Knowledge Bulletproofs and Confidential Asset Settlement Protocol.
//! Implements non-interactive logarithmic range proofs, Inner-Product Arguments,
//! Dual-Key Stealth Address Protocol (DKSAP), and homomorphic balance preservation.

pub mod errors;
pub mod generators;
pub mod inner_product;
pub mod pedersen;
pub mod range_proof;
pub mod stealth;
pub mod transcript;
pub mod confidential_tx;

// Primary re-exports
pub use errors::ProofError;
pub use generators::BulletproofGenerators;
pub use inner_product::InnerProductProof;
pub use pedersen::{ValueCommitment, inner_product_scalars, multiscalar_mul};
pub use range_proof::RangeProof;
pub use stealth::{OneTimeStealthAddress, StealthKeypair, StealthMetaAddress};
pub use transcript::ProofTranscript;
pub use confidential_tx::{
    ConfidentialTransaction, SchnorrSignature, TxInput, TxOutput,
};

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Serialization / format error: {0}")]
    FormatError(String),

    #[error("Vector length mismatch: expected {expected}, got {actual}")]
    LengthMismatch { expected: usize, actual: usize },

    #[error("Invalid bit length: {0} (must be 8, 16, 32, or 64)")]
    InvalidBitLength(usize),

    #[error("Vector length {0} is not a power of two")]
    NonPowerOfTwo(usize),

    #[error("Transaction balance mismatch: inputs do not equal outputs + fee")]
    BalanceMismatch,

    #[error("Signature verification error: {0}")]
    SignatureError(String),

    #[error("Range proof error: {0}")]
    RangeProofError(String),

    #[error("Generator capacity exceeded: required {required}, available {available}")]
    GeneratorCapacityExceeded { required: usize, available: usize },
}

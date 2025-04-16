pub mod rsa256;

/// The error type for signing operations
pub enum SigningError {
    InvalidKey(String),
    InvalidData(String),
    InvalidAlgorithm(String),
}
use serde::{Deserialize, Serialize};

use crate::{encoding, signing, model::header::{Header, Algorithm}};

pub mod rsa;

/// Signs the token with the given header and claims using the specified signing key.
/// 
/// # Arguments
/// * `header` - The header of the JWT
/// * `claims` - The claims to be included in the token, which can be any serializable type.
/// * `signing_key` - The key used to sign the token, read from the file directly as a string
/// * `T` - The type of the claims, which must implement `serde::Serialize`, `serde::Deserialize` and `Clone`.
/// 
/// # Returns
/// * `Result<String, SigningError>` - The encoded & signed token as a string, or an error if signing fails.
pub fn sign<'a, T: Serialize + Deserialize<'a> + Clone>(header: &Header, claims: &T, signing_key: &str) -> Result<String, SigningError> {
    
    // Check the header for the algorithm
    let algorithm = header.alg.clone();

    // Encode the header and claims
    let encoded_header = encoding::header::encode(header).map_err(|_| SigningError::InvalidData(format!("Failed to encode header")))?;
    let encoded_claims = encoding::claims::encode(claims).map_err(|_| SigningError::InvalidData(format!("Failed to encode claims")))?;

    // Sign the token using the correct algorithm 
    let signed_token = signing::rsa::hmac_rsa(&encoded_header, &encoded_claims, signing_key, algorithm)?;
    Ok(signed_token)
}

/// The error type for signing operations
pub enum SigningError {
    InvalidKey(String),
    InvalidData(String),
    InvalidAlgorithm(String),
}
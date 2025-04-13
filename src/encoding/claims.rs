use base64::Engine;
use serde::Serialize;

use super::ENCODING_ENGINE;

/// Encodes claims into a base64 string.
/// 
/// # Arguments
/// * `claims` - A reference to the claims to be encoded. Must implement the `Serialize` trait.
/// 
/// # Returns
/// A base64 encoded string representation of the claims.
pub fn encode<T: Serialize>(claims: &T) -> Result<String, ClaimsEncodeError> {
    // Convert the claims to a JSON string
    let claims_json = serde_json::to_string(claims).unwrap();

    // Check for missing fields
    // exp - expiration time
    if !claims_json.contains("exp") {
        return Err(ClaimsEncodeError::MissingFieldError("exp".to_string()));
    }

    // sub - subject
    if !claims_json.contains("sub") {
        return Err(ClaimsEncodeError::MissingFieldError("sub".to_string()));
    }

    // Encode the JSON string to base64
    let claims_base64: String = ENCODING_ENGINE.encode(claims_json);
    Ok(claims_base64)
}

/// Error type returned when encoding claims fails.
/// 
/// # Variants
/// * `JsonError`: JSON serialization error
/// * `MissingFieldError`: Missing field error
pub enum ClaimsEncodeError {
    /// JSON serialization error
    JsonError(serde_json::Error),
    /// Missing field error
    MissingFieldError(String),
}
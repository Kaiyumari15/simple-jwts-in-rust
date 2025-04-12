use serde::{Deserialize, Serialize};

/// Decodes claims from a base64 string into the user defined type T
/// 
/// Does not check for exp etc, as if this is expected by your struct and is not present an error will occur during deserialization
/// 
/// # Arguments
/// * `claims`: The base64 encoded string to decode
/// * T: The type to decode the claims into. Must implement the `Deserialize` trait.
/// 
/// # Returns
/// A `Result` containing either the decoded claims or an error
pub fn decode<T: Deserialize<'static>>(claims: &str) -> Result<T, ClaimsDecodeError> {
    // Decode the base64 string
    let claims_json = base64::engine::general_purpose::STANDARD.decode(claims).map_err(|e| ClaimsDecodeError::Base64Error(e))?;
    
    // Convert the decoded bytes to a JSON string
    let claims_json_str = String::from_utf8(claims_json).map_err(|e| ClaimsDecodeError::Other(e.to_string()))?;
    
    // Deserialize the JSON string into the specified type
    let claims: T = serde_json::from_str(&claims_json_str).map_err(|e| ClaimsDecodeError::JsonError(e))?;
    
    Ok(claims)
}

#[derive(Debug, Clone)]
/// Type returned when decoding claims fails
/// 
/// # Variants
/// * `JsonError`: JSON deserialization error
/// * `Base64Error`: Base64 decoding error
/// * `MissingFieldError`: Missing field error
/// * `Other`: Other errors
pub enum ClaimsDecodeError {
    /// JSON deserialization error
    JsonError(serde_json::Error),
    /// Base64 decoding error
    Base64Error(base64::DecodeError),
    /// Other errors
    Other(String),
}
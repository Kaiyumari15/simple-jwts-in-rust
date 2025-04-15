use base64::Engine;
use serde::Deserialize;

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
pub fn decode<T: for<'a> Deserialize<'a> + Clone + ToOwned>(claims: &str) -> Result<T, ClaimsDecodeError> {
    
    // Add padding if needed
    let padding_needed = claims.len() % 4;
    let padding = "=".repeat(padding_needed);
    let claims = format!("{}{}", claims, padding);
    
    // Decode the base64 string
    let claims_json: Vec<u8> = base64::engine::general_purpose::STANDARD.decode(claims).map_err(|e| ClaimsDecodeError::Base64Error(e))?;

    // Deserialize the JSON bytes
    let bytes: &[u8]= claims_json.as_slice();
    let result: T = serde_json::from_slice(bytes).map_err(|e| ClaimsDecodeError::JsonError(e))?;

    let result = result.clone();

    Ok(result)
}

#[derive(Debug)]
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
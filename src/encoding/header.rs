use base64::Engine;
use serde_json::json;

use crate::model::header::Header;

use super::ENCODING_ENGINE;

/// Encodes a header into a base64 string
/// 
/// # Arguments
/// * `header` - A reference to the header to be encoded
/// 
/// # Returns
/// A base64 encoded string representation of the header
pub fn encode(header: &Header) -> Result<String, HeaderEncodeError> {

    // Convert the header to a JSON string
    let header = json!({
        "typ": "JWT",
        "alg": header.alg,
    });
    let header_json = serde_json::to_string(&header).map_err(|e| HeaderEncodeError::JsonError(e))?;

    // Encode the JSON string to base64 
    let header_base64: String = ENCODING_ENGINE.encode(header_json);
    Ok(header_base64)
}

#[derive(Debug)]
/// Error type returned when encoding a header fails
/// 
/// # Variants
/// * `JsonError`: JSON serialization error
/// * `Base64Error`: Base64 encoding error
/// * `Other`: Other errors
pub enum HeaderEncodeError {
    /// JSON serialization error
    #[allow(dead_code)]
    JsonError(serde_json::Error),
}
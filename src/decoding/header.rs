use std::str::FromStr;

use base64::Engine;
use serde_json::Value;

use crate::model::header::{Algorithm, Header};

/// Decodes a base64 string into a header
/// 
/// # Arguments
/// * `base64_str`: The base64 encoded string to decode
/// 
/// # Returns
/// A `Result` containing either the decoded header or an error
pub fn decode(base64_str: &str) -> Result<Header, HeaderDecodeError> {
    // Decode a base64 string into a vector of bytes
    let decoded_bytes = base64::engine::general_purpose::STANDARD.decode(base64_str).map_err(|e| HeaderDecodeError::Base64Error(e))?;

    // Convert the vector of bytes to a String
    let decoded_string = String::from_utf8(decoded_bytes).map_err(|e| HeaderDecodeError::Other(e.to_string()))?;

    // Convert the String into a JSON object
    let full_header: Value = serde_json::from_str(&decoded_string).map_err(|e| HeaderDecodeError::JsonError(e))?;

    // Take the algorithm and construct the header object
    let alg = full_header["alg"].as_str().ok_or_else(|| HeaderDecodeError::MissingFieldError("Missing 'alg' field".to_string()))?;
    let alg = Algorithm::from_str(alg).map_err(|_| HeaderDecodeError::UnsupportedAlgorithm(alg.to_string()))?;
    
    // Create a new header object with the algorithm
    let header = Header::new(alg);
    Ok(header)
}

#[derive(Debug)]
/// Error type returned when decoding a header fails
/// 
/// # Variants
/// * `JsonError`: JSON deserialization error
/// * `Base64Error`: Base64 decoding error
/// * `UnsupportedAlgorithm`: Unsupported algorithm error
/// * `MissingFieldError`: Missing field error
/// * `Other`: Other errors
pub enum HeaderDecodeError {
    /// JSON deserialization error
    JsonError(serde_json::Error),
    /// Base64 decoding error
    Base64Error(base64::DecodeError),
    /// Unsupported algorithm error
    UnsupportedAlgorithm(String),
    /// Missing field error
    MissingFieldError(String),
    /// Other errors
    Other(String),
}
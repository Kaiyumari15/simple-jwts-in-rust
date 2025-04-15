pub mod rsa256; 

use serde::{Deserialize, Serialize};

use crate::model::header::Algorithm;
use crate::decoding;

/// Verify a token using the given algorithm and (public/verifying) key
/// 
/// Does not check any of the claims, e.g. exp. This is to be done by the caller
/// 
/// # Arguments
/// * `signed_token` - A string representing the signed token (header.payload.signature)
/// * `key_from_pem` - A string representing the public key in PEM format
/// * `T` - The type to deserialize the claims into
/// 
/// # Returns
/// * `Result<T, VerifyingTokenError>` - Returns the claims if the token is valid, or an error if it is not
/// 
/// # Example
/// ```rust
/// use crate::verifying::verify_token;
/// use crate::model::claims::Claims;
/// 
/// let token = "pretend_this.is_a.valid_signed_token";
/// let public_key = "pretend_this_is_a_valid_public_key_from_a_pem_file";
/// let claims: Claims = verify_token(token, public_key).unwrap();
/// ``````
pub fn verify_token<T: Clone + Serialize + for<'a> Deserialize<'a>>(signed_token: &str, key_from_pem: &str) -> Result<T, VerifyingTokenError> {
    #[allow(unused_assignments)]
    let mut verified: bool = false;

    // Split the token into parts
    let split_token = signed_token.split('.').collect::<Vec<&str>>(); 
    
    // Read the algorithm from the token
    let alg = decoding::header::decode(&split_token[0]).unwrap().alg; // This should be updated for better error handling

    // Verify the token using the algorithm
    match alg {
        Algorithm::RS256 => verified = rsa256::verify(&split_token, key_from_pem),
    }

    // Return an error if not verified
    if !verified {
        return Err(VerifyingTokenError::InvalidSignature);
    };

    // Return the claims
    let claims: T = decoding::claims::decode(&split_token[1]).unwrap();
    Ok(claims)

}

/// Type returned if there is an error when verifying a token
/// 
/// # Variants
/// * `InvalidSignature` - The signature is invalid
/// * `DeserializingHeader` - There was an error deserializing the header
/// * `DeserializingClaims` - There was an error deserializing the claims into the given type
/// * `Other` - There was an unknown error
pub enum VerifyingTokenError {
    /// The signature is invalid
    InvalidSignature,
    /// There was an error deserializing the header
    DeserializingHeader,
    /// There was an error deserializing the claims into the given type
    DeserializingClaims,
    /// There was an unkown error
    Other(String),
}
use base64::Engine;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::pss::BlindedSigningKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::sha2::{Sha256, Sha512};
use rsa::RsaPrivateKey;
use rsa::rand_core::OsRng;

use crate::encoding::ENCODING_ENGINE;
use crate::model::header::Algorithm;

use super::SigningError;

/// This function signs a JWT using RSA256 with a private key in PEM format.
/// 
/// # Arguments
/// * `header` - A reference to the base64 encoded JWT header as a string.
/// * `body` - A reference to the base64 encoded JWT body as a string.
/// * `key_from_pem` - A reference to the private key in PEM format as a string.
/// 
/// # Returns
/// A string representing the signed JWT.
/// 
/// # Example
/// 
/// ```rust
/// use crate::signing::rsa256::hmac_rsa256;
/// 
/// let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // Example base64 encoded header
/// let body = "eyJleHAiOjE0ODUxNDA5ODQsImlhdCI6MTQ4NTEzNzM4NCwiaXNzIjoiYWNtZS5jb20iLCJzdWIiOiIyOWFjMGMxOC0wYjRhLTQyY2YtODJmYy0wM2Q1NzAzMThhMWQiLCJhcHBsaWNhdGlvbklkIjoiNzkxMDM3MzQtOTdhYi00ZDFhLWFmMzctZTAwNmQwNWQyOTUyIiwicm9sZXMiOltdfQ"; // Example base64 encoded body
/// let key = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"; // Example PEM formatted private key
/// 
/// let signed_jwt = hmac_rsa256(header, body, key); // Call the function to sign the JWT
/// ``````
pub fn hmac_rsa(header: &str, body: &str, key_from_pem: &str, algorithm: Algorithm) -> Result<String, SigningError> {

    // Create a random number
    let mut rng = OsRng; 

    // Concatenate the header and body with a dot
    let data = format!("{}.{}", header, body); 

    // Decode the private key for use 
    let private_key = RsaPrivateKey::from_pkcs1_pem(key_from_pem).map_err(|err| SigningError::InvalidKey(err.to_string()))?; // currently assumes pkcs1, will need to change to allow for pkcs8 as well

    // Sign the header and body using the signing key with the correct algorithm
    // This must be done in a match statement as the algorithm is not known at compile time and results in different types of keys
    let signature = match algorithm {
        Algorithm::RS256 => BlindedSigningKey::<Sha256>::new(private_key).try_sign_with_rng(&mut rng, data.as_bytes()).map_err(|err| SigningError::InvalidData(err.to_string()))?,
        Algorithm::RS512 => BlindedSigningKey::<Sha512>::new(private_key).try_sign_with_rng(&mut rng, data.as_bytes()).map_err(|err| SigningError::InvalidData(err.to_string()))?,
    };
    
    // Encode the signature in base 64
    let signature = signature.to_vec();
    let signature_base64 = ENCODING_ENGINE.encode(signature);

    // Return the signed JWT
    Ok(format!("{}.{}.{}", header, body, signature_base64))
}
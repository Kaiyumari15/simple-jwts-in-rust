use base64::Engine;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::Signature;
use rsa::sha2::Sha512;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use rsa::{pss::VerifyingKey, sha2::Sha256};

use crate::model::header::Algorithm;

use super::VerifyingTokenError;

/// Verify a token using RSA256 and an RSA public key
/// 
/// # Arguments
/// * `token` - A slice of strings representing the token parts (header, payload, signature)
/// * `public_key` - A string representing the RSA public key in PEM format
/// 
/// # Returns
/// * `bool` - Returns true if the token signature is valid, false otherwise
pub fn verify(token: &[&str], public_key: &str, algorithm: &Algorithm) -> Result<bool, VerifyingTokenError> {
    if token.len() != 3 {
        return Err(VerifyingTokenError::Other("Token must have 3 parts".to_string()));
    }

    // Seperate the token parts
    let header = token[0];
    let payload = token[1];
    let signature = token[2];

    let decoded_signature = crate::decoding::DECODING_ENGINE.decode(signature).unwrap();
    let decoded_signature = decoded_signature.as_slice();

    // Get the public key
    let rsa_pub = RsaPublicKey::from_public_key_pem(public_key).map_err(|_| VerifyingTokenError::VerifyingKey)?;
    let data = format!("{}.{}", header, payload);

    // Match the algorithm to create the signature
    // and verify the token
    // must be done in this match statement as the keys are different types depending on the algorithm
    match algorithm {
        Algorithm::RS256 => {
            let verifying_key = VerifyingKey::<Sha256>::new(rsa_pub);
            let signature = Signature::try_from(decoded_signature).expect("Failed to parse signature from bytes");
            return Ok(verifying_key.verify(data.as_bytes(), &signature).is_ok())
        }
        Algorithm::RS512 => {
            let verifying_key = VerifyingKey::<Sha512>::new(rsa_pub);
            let signature = Signature::try_from(decoded_signature).expect("Failed to parse signature from bytes");
            return Ok(verifying_key.verify(data.as_bytes(), &signature).is_ok())
        }
    }
}
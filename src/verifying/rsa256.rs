use base64::Engine;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::Signature;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use rsa::{pss::VerifyingKey, sha2::Sha256};

/// Verify a token using RSA256 and an RSA public key
/// 
/// # Arguments
/// * `token` - A slice of strings representing the token parts (header, payload, signature)
/// * `public_key` - A string representing the RSA public key in PEM format
/// 
/// # Returns
/// * `bool` - Returns true if the token signature is valid, false otherwise
pub fn verify(token: &[&str], public_key: &str) -> bool {
    if token.len() != 3 {
        return false;
    }

    // Seperate the token parts
    let header = token[0];
    let payload = token[1];
    let signature = token[2];

    let decoded_signature = crate::decoding::DECODING_ENGINE.decode(signature).unwrap();
    let decoded_signature = decoded_signature.as_slice();

    // Check the signature
    let rsa_pub = RsaPublicKey::from_public_key_pem(public_key).expect("Failed to parse PEM file");
    let verifying_key = VerifyingKey::<Sha256>::new(rsa_pub);
    let data = format!("{}.{}", header, payload);
    let signature = Signature::try_from(decoded_signature).expect("Failed to parse signature from bytes");
    let verify = verifying_key.verify(data.as_bytes(), &signature).is_ok();
    verify
}
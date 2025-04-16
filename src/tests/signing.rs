use serde::{Deserialize, Serialize};

use crate::{encoding, signing, model::header::{Algorithm, Header}};

#[test]
fn test_signing_successful() {
    // Define a claims struct
    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    struct Claims {
        exp: usize,
        sub: String,
    }

    // Create a header and claims
    let header = Header::new(Algorithm::RS256);
    let claims = Claims {
        exp: 100000000,
        sub: "123456".to_string(),
    };

    // Encode the header and claims
    let encoded_header = encoding::header::encode(&header).unwrap();
    let encoded_claims = encoding::claims::encode(&claims).unwrap();

    // Read in the PEM file
    let pem_path = "src/tests/test_private.pem";
    let pem = std::fs::read_to_string(pem_path).expect("Failed to read PEM file");

    // Sign the token
    let signed_token = signing::rsa256::hmac_rsa256(&encoded_header, &encoded_claims, &pem);

    dbg!(signed_token);
}
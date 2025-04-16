use serde::{Deserialize, Serialize};

use crate::{model::header::Algorithm, verifying};

#[test]
fn test_verify_successful() {
    // Define a claims struct

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    struct Claims {
        exp: usize,
        sub: String,
    }

    // A previously generated token
    let signed_token = r#"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEwMDAwMDAwMCwic3ViIjoiMTIzNDU2In0.kfXA6hQhrnqRYV5NziIkjZf8CZBFcYzJhQEU-y1fV_2hM7cUHSzFN-tBWr4u3tH-PXhnnWCyH9nNzNI8hr3SRkaFFggyODE8t3rpmpZy67wefByCVtyNf-gKGg101P0W-bazgJ3nr1ufKTQQ7eBuN_89NXCUlsdKEHARkVypZxNJUsDArSv6djnbAAKO6OPQhFYZuG2lXiUIW6PZ0C8lT1L326RS4YtcpC9sZVG-47k2Iwyh7oT4cyPk405Vf1CcCEp3PITL2NzAGVq9A1OvcURwmavMT0xuc7mhOpZiMGIDHtUu9Qd1DtUPouUfZxDYotNRtaYMZ5jQMqJWkp3I0g"#;

    // Read in the public key
    let public_path = "src/tests/test_public.pem";
    let public_key = std::fs::read_to_string(public_path).expect("Failed to read PEM file");

    // Split the token into its parts
    let parts: Vec<&str> = signed_token.split('.').collect();
    assert_eq!(parts.len(), 3, "Token should have 3 parts: header, body, and signature");

    // Verify the token using the public key and algorithm
    let verified = verifying::rsa::verify(&parts, &public_key, &Algorithm::RS256);
    assert!(verified.is_ok(), "Token verification should not return an error");
    assert_eq!(verified.unwrap(), true, "Token should be verified successfully");
}
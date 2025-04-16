#[cfg(test)]
mod header {
    use crate::encoding::header::encode;
    use crate::model::header::{Header, Algorithm};

    #[test]
    /// Tests the encoding of a JWT header.
    /// 
    /// # Description
    /// Tests the encoding of a JWT header using the `encode` function.
    pub fn test_header_encode_successful() {
        let encoded_header = encode(&Header::new(Algorithm::RS256)).unwrap();

        // Header1 assumes "typ" first
        // Header2 assumes "alg" first
        let expected_header1 = r#"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"#;
        let expected_header2 = r#"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"#;

        // Check if the encoded header is equal to one of the expected 
        if encoded_header == expected_header1 || encoded_header == expected_header2 {
            assert!(true);
        } else {
            assert!(false, "Header encoding failed. Expected: {} or {}, got: {}", expected_header1, expected_header2, encoded_header);
        }
    }
}

#[cfg(test)]
mod claims {
    use crate::encoding::claims::encode;
    use serde::Serialize;

    #[test]
    /// Tests the encoding of claims in a JWT.
    /// 
    /// # Description
    /// Tests the encoding of claims using the `encode` function.
    /// The test creates a claims struct, serializes it, and checks if the encoding is successful.
    pub fn test_claims_encode_successful() {

        // Define a claims struct
        #[derive(Serialize)]
        struct Claims {
            exp: usize,
            sub: String,
        }

        // Create an instance of the claims struct
        let claims = Claims {
            exp: 10000000000,
            sub: "123456".to_string(),
        };

        // Encode the claims using the encode function
        let encoded_claims = encode(&claims).unwrap();

        // Define the expected encoded claims string
        let expected_encoded = r#"eyJleHAiOjEwMDAwMDAwMDAwLCJzdWIiOiIxMjM0NTYifQ"#;

        assert_eq!(encoded_claims, expected_encoded, "Claims encoding failed. Expected: {}, got: {}", expected_encoded, encoded_claims);
    }
}
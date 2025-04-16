#[cfg(test)]
mod header {
    use crate::decoding::header::decode;
    use crate::model::header::{Header, Algorithm};

    #[test]
    /// Tests the decoding of a JWT header.
    fn test_header_decode_successful() {
        let encoded_header = r#"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"#;
        let decoded_header: Header = decode(encoded_header).unwrap();

        // Check if the decoded header is equal to the expected header
        let expected_header = Header::new(Algorithm::RS256);
        assert_eq!(decoded_header, expected_header, "Header decoding failed. Expected: {:?}, got: {:?}", expected_header, decoded_header);
    }
}

#[cfg(test)]
mod claims {
    use serde::Deserialize;
    use crate::decoding::claims::decode;
    
    #[test]
    /// Tests the decoding of a JWT claims.
    fn test_claims_decode_successful() {
        let encoded_claims = r#"eyJleHAiOjEwMDAwMDAwMDAwLCJzdWIiOiIxMjM0NTYifQ"#;

        // Define a claims struct
        #[derive(Deserialize, Clone, PartialEq, Debug)]
        struct Claims {
            exp: usize,
            sub: String,
        }

        // Create an instance of the claims struct
        let expected_claims = Claims {
            exp: 10000000000,
            sub: "123456".to_string(),
        };

        // Decode the claims using the decode function
        let decoded_claims: Claims = decode(encoded_claims).unwrap();

        assert_eq!(expected_claims, decoded_claims, "Claims decoding failed. Expected: {:?}, got: {:?}", expected_claims, decoded_claims);
    }
}
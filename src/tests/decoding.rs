#[cfg(test)]
mod header {
    use crate::decoding::header::decode;
    use crate::model::header::{Header, Algorithm};

    #[test]
    /// Tests the decoding of a JWT header.
    /// 
    /// # Description
    /// Tests the decoding of a JWT header using the `decode` function.
    fn test_header_decode_successful() {
        // Define the encoded header string
        let decoded_header = r#"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"#;

        let decoded = decode(decoded_header).unwrap();
        let expected = Header::new(Algorithm::RS256);

        // Check if the decoded header is equal to the expected header
        assert_eq!(decoded, expected, "Header decoding failed. Expected: {:?}, got: {:?}", expected, decoded);
    }
}

#[cfg(test)]
mod claims {
    use crate::decoding::claims::decode;
    use serde::{Deserialize, Serialize};


    #[test]
    fn test_claims_decode_successful() {
        // Define a claims struct
        #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
        struct Claims {
            exp: usize,
            sub: String,
        }

        // Define the expected
        let expected = Claims {
            exp: 10000000000,
            sub: "123456".to_string(),
        };

        // Define the encoded claims string
        let encoded_claims = r#"eyJleHAiOjEwMDAwMDAwMDAwLCJzdWIiOiIxMjM0NTYifQ"#;

        // Decode the claims using the decode function
        let decoded: Claims = decode(encoded_claims).unwrap();

        // Check if the decoded claims are equal to the expected claims
        assert_eq!(decoded, expected, "Claims decoding failed. Expected: {:?}, got: {:?}", expected, decoded);
    }
}
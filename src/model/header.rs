use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::decoding::header::HeaderDecodeError;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    pub alg: Algorithm,
}

impl Header {

    /// Creates a new JWT header with the specified algorithm.
    /// 
    /// # Arguments
    /// * - `algorithm`: The algorithm to use for signing the JWT.
    /// 
    /// # Returns
    /// * A new `Header` instance with the specified algorithm.
    /// 
    /// # Example
    /// ```rust
    /// use jwt::model::header::{Header, Algorithm};
    /// 
    /// let algorithm = Algorithm::HS256;
    /// let header = Header::new(algorithm);
    /// ```
    pub fn new(algorithm: Algorithm) -> Self {
        Header {
            alg: algorithm,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// The algorithm used to sign the JWT.
/// Currently, only HS256 is supported.
/// 
/// # Example
/// ```rust
/// use jwt::model::header::Algorithm;
/// 
/// let algorithm = Algorithm::HS256;
/// let header = Header::new(algorithm);
/// ```
pub enum Algorithm {
    RS256,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::RS256 => write!(f, "RS256"),
        }
    }
}

impl FromStr for Algorithm {
    type Err = HeaderDecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RS256" => Ok(Algorithm::RS256),
            _ => Err(HeaderDecodeError::UnsupportedAlgorithm(s.to_string())),
        }
    }
}
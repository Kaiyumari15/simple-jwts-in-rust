use std::fmt::Display;

use serde::{Deserialize, Serialize};

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
    HS256,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::HS256 => write!(f, "HS256"),
        }
    }
}
use base64::{alphabet, engine::{self, general_purpose}};

pub mod claims;
pub mod header;

/// encoding engine for base64 URL safe encoding without padding
/// following: https://datatracker.ietf.org/doc/html/rfc7515#section-5.1 documentation
pub const ENCODING_ENGINE: engine::GeneralPurpose =
engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
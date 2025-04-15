use base64::{alphabet, engine::{self, general_purpose}};

pub mod header;
pub mod claims;

pub const DECODING_ENGINE: engine::GeneralPurpose =
engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
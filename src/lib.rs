mod decoding;
mod encoding;
mod model;
mod signing;
mod tests;
mod verifying;

pub use crate::signing::sign;
pub use crate::verifying::verify;
pub use crate::decoding::{ claims::decode as decode_claims, header::decode as decode_header };
pub use crate::model::header::{ Algorithm, Header };
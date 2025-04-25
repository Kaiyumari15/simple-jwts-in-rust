mod decoding;
mod encoding;
mod model;
mod signing;
mod tests;
mod verifying;

pub use crate::signing::{sign, SigningError as SignTokenError};
pub use crate::verifying::{verify, VerifyingTokenError as VerifyTokenError};
pub use crate::decoding::{claims::{decode as decode_claims, ClaimsDecodeError as DecodeClaimsError}, header::{decode as decode_header, HeaderDecodeError as DecodeHeaderError}};
pub use crate::encoding::{claims::{encode as encode_claims, ClaimsEncodeError as EncodeClaimsError}, header::{encode as encode_header, HeaderEncodeError as EncodeHeaderError}};
pub use crate::model::header::{ Algorithm, Header };
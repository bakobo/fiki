//! fiki — sign and verify HTTP requests with a bare Ed25519 key as the identifier.
//!
//! Standard [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html), with one lens: an Ed25519
//! public key is rendered as a non-transferable AID (CESR `Ed25519N`, a 44-character `B…` string),
//! so the identifier is the verifying key and a verifier resolves nothing.
//!
//! See `this.i` @07wstqk7 in <https://github.com/bakobo/fiki> for why this is a library of its own.

mod base;
mod errors;
mod keys;
mod messages;
mod sfv;

pub use base::{signature_base, SignatureParams, CONTENT_DIGEST, DEFAULT_COVERED, DERIVED};
pub use errors::{Error, Kind, Result};
pub use keys::{to_aid, verifying_key, Key};
pub use messages::{
    content_digest, sign_request, verify_request, SignOptions, Verdict, VerifyOptions, ALG,
    DEFAULT_SKEW,
};

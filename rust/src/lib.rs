//! fiki — sign and verify HTTP requests with a bare Ed25519 key as the identifier.
//!
//! Standard [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html), with one lens: an Ed25519
//! public key is rendered as a non-transferable AID (CESR `Ed25519N`, a 44-character `B…` string),
//! so the identifier is the verifying key and a verifier resolves nothing.
//!
//! See `this.i` @07wstqk7 in <https://github.com/bakobo/fiki> for why this is a library of its own.

/// The conformance contract this port satisfies (`this.i` @4fhrre0m).
///
/// Two artifacts interoperate when their declared vectors format matches, whatever their own
/// version numbers say — so this is the number to compare, not the release. Monotonic, because a
/// conformance contract has no meaningful minor: an implementation either satisfies the vectors or
/// it does not.
pub const VECTORS_FORMAT: u32 = 1;

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

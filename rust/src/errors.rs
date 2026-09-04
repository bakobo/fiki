//! fiki's error taxonomy (`this.i` @8zw78n0v).
//!
//! The variant NAMES are a cross-language contract rather than an implementation detail:
//! `vectors/refusals.json` records the name fiki reports for each refusal, and every port asserts
//! on it. So a port that folds two conditions together fails a vector rather than passing quietly,
//! and heti — which maps these onto its own codes — can be told what happened by a client in any
//! language.
//!
//! The granularity comes from heti's taxonomy, which distinguishes a missing header from an
//! unparsable one, per header, so a sender can be told which header to fix rather than handed the
//! pair.

use std::fmt;

/// Every error fiki returns about a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: Kind,
    pub message: String,
    /// The offending value, when there is one. Carried structurally rather than in the message, so
    /// a consumer translating fiki's errors into its own vocabulary is not reading prose.
    pub detail: Option<String>,
}

/// The condition a refusal names. The `Display` spelling is what the shared vectors pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    // Something the request needs is absent.
    MissingSignature,
    MissingSignatureInput,
    MissingSignatureLabel,
    MissingKey,
    MissingComponent,

    // Something the request carries cannot be read.
    MalformedSignature,
    MalformedSignatureInput,
    MalformedSignatureLabel,
    MalformedSignatureValue,
    MalformedKey,
    MalformedDigest,

    // fiki understood the request and will not handle it.
    UnsupportedComponent,
    UnsupportedAlgorithm,
    UncoveredBody,

    // The request is signed and a stated policy refuses it anyway (`this.i` @67shl6c5).
    SignatureExpired,
    SignatureTooOld,

    // The request was read, and it does not hold up.
    DigestMismatch,
    SignatureMismatch,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Kind::MissingSignature => "MissingSignature",
            Kind::MissingSignatureInput => "MissingSignatureInput",
            Kind::MissingSignatureLabel => "MissingSignatureLabel",
            Kind::MissingKey => "MissingKey",
            Kind::MissingComponent => "MissingComponent",
            Kind::MalformedSignature => "MalformedSignature",
            Kind::MalformedSignatureInput => "MalformedSignatureInput",
            Kind::MalformedSignatureLabel => "MalformedSignatureLabel",
            Kind::MalformedSignatureValue => "MalformedSignatureValue",
            Kind::MalformedKey => "MalformedKey",
            Kind::MalformedDigest => "MalformedDigest",
            Kind::UnsupportedComponent => "UnsupportedComponent",
            Kind::UnsupportedAlgorithm => "UnsupportedAlgorithm",
            Kind::UncoveredBody => "UncoveredBody",
            Kind::SignatureExpired => "SignatureExpired",
            Kind::SignatureTooOld => "SignatureTooOld",
            Kind::DigestMismatch => "DigestMismatch",
            Kind::SignatureMismatch => "SignatureMismatch",
        };
        f.write_str(name)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl Error {
    pub(crate) fn new(kind: Kind, message: impl Into<String>) -> Self {
        Error {
            kind,
            message: message.into(),
            detail: None,
        }
    }

    pub(crate) fn detailed(
        kind: Kind,
        message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Error {
            kind,
            message: message.into(),
            detail: Some(detail.into()),
        }
    }
}

/// The result of anything fiki can refuse.
pub type Result<T> = std::result::Result<T, Error>;

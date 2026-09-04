//! Signing and verifying whole HTTP requests (`this.i` @2hwvpm42, @7xrx5evg, @67shl6c5).
//!
//! The keyid is always the signer's raw key and is not overridable, so "the request carries its own
//! verifying key" holds for every fiki-signed request. A body is always covered or the signature is
//! refused. And a verifier states a freshness policy or explicitly declines one.
//!
//! The bound worth stating plainly: fiki cannot cover a body it was never given. The guarantee is
//! "hand fiki the body and it is covered, or fiki refuses" — a caller who omits it gets a valid
//! signature over a request whose body nothing protects, and no library can detect that.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier};
use sha2::{Digest, Sha256, Sha512};

use crate::base::{
    component_lines, lower_headers, signature_base, SignatureParams, CONTENT_DIGEST,
    DEFAULT_COVERED,
};
use crate::errors::{Error, Kind, Result};
use crate::keys::{b64std, decode, to_aid, verifying_key, Key};
use crate::sfv::{parse_dictionary, serialize_inner_list, InnerList, Value};

/// The only signature algorithm fiki produces or accepts.
pub const ALG: &str = "ed25519";

/// Two hosts disagreeing by a second is ordinary; a verifier that treats it as an attack is
/// unusable.
pub const DEFAULT_SKEW: i64 = 5;

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The RFC 9530 `Content-Digest` header value for a body.
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", b64std(&Sha256::digest(body)))
}

fn now_or(now: Option<i64>) -> i64 {
    now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

/// Everything beyond the request itself.
#[derive(Debug, Default, Clone)]
pub struct SignOptions {
    pub body: Option<Vec<u8>>,
    /// `None` takes [`DEFAULT_COVERED`]. Naming your own is what turns a body without a digest
    /// from a helpful addition into a refusal.
    pub covered: Option<Vec<String>>,
    pub created: Option<i64>,
    pub label: Option<String>,
    pub expires: Option<i64>,
    pub nonce: Option<String>,
    pub tag: Option<String>,
}

/// Sign a request and return the headers to add to it.
pub fn sign_request(
    key: &Key,
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    opts: &SignOptions,
) -> Result<BTreeMap<String, String>> {
    let mut sending = headers.clone();

    // Whether the caller CHOSE the covered set is the difference between fiki helping and fiki
    // overriding. On the default path a body simply gets covered; on an explicit path, silently
    // adding a component would mean the signature covers something the caller did not ask for.
    let chosen = opts.covered.is_some();
    let mut components: Vec<String> = match &opts.covered {
        Some(covered) => covered.iter().map(|c| c.to_ascii_lowercase()).collect(),
        None => DEFAULT_COVERED.iter().map(|c| c.to_string()).collect(),
    };

    if let Some(body) = &opts.body {
        if !components.iter().any(|c| c == CONTENT_DIGEST) {
            if chosen {
                return Err(Error::new(
                    Kind::UncoveredBody,
                    "This request carries a body, but the covered components do not include \
                     \"content-digest\", so the signature would not bind the body.",
                ));
            }
            components.push(CONTENT_DIGEST.to_string());
        }
        if !sending
            .keys()
            .any(|name| name.to_ascii_lowercase() == CONTENT_DIGEST)
        {
            sending.insert("Content-Digest".into(), content_digest(body));
        }
    }

    let params = SignatureParams {
        created: Some(opts.created.unwrap_or_else(|| now_or(None))),
        keyid: Some(key.keyid()),
        alg: Some(ALG.into()),
        expires: opts.expires,
        nonce: opts.nonce.clone(),
        tag: opts.tag.clone(),
    };
    let base = signature_base(method, url, &sending, &components, &params)?;
    let signature = key.sign(&base);

    let text = String::from_utf8_lossy(&base);
    let marker = "\"@signature-params\": ";
    let rendered = &text[text.rfind(marker).map(|at| at + marker.len()).unwrap_or(0)..];
    let label = opts.label.clone().unwrap_or_else(|| "sig".to_string());

    let mut out = BTreeMap::new();
    out.insert("Signature-Input".into(), format!("{label}={rendered}"));
    out.insert(
        "Signature".into(),
        format!("{label}=:{}:", b64std(&signature)),
    );
    if let Some(made) = sending.get("Content-Digest") {
        if !headers
            .keys()
            .any(|name| name.to_ascii_lowercase() == CONTENT_DIGEST)
        {
            out.insert("Content-Digest".into(), made.clone());
        }
    }
    Ok(out)
}

/// The outcome of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub aid: String,
    pub covered: Vec<String>,
}

/// The verifier's policy and the body it has in hand.
///
/// `max_age` is an `Option<i64>` that the caller must fill in one way or the other: seconds of
/// tolerance, or an explicit `None` to decline the check. Both defaults would be wrong
/// (`this.i` @67shl6c5).
#[derive(Debug, Default, Clone)]
pub struct VerifyOptions {
    pub max_age: Option<i64>,
    pub body: Option<Vec<u8>>,
    pub expected_aid: Option<String>,
    pub skew: Option<i64>,
    pub now: Option<i64>,
}

/// Verify a signed request.
pub fn verify_request(
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    opts: &VerifyOptions,
) -> Result<Verdict> {
    let found = lower_headers(headers);
    let (list, signature) = read(&found)?;

    if let Some(Value::Text(alg)) = list.param("alg") {
        if alg != ALG {
            return Err(Error::detailed(
                Kind::UnsupportedAlgorithm,
                format!("This signature is made with \"{alg}\", and fiki verifies only {ALG}."),
                alg,
            ));
        }
    }

    let aid = resolve(opts.expected_aid.as_deref(), &list)?;
    let public = verifying_key(&aid)?;

    let mut lines = component_lines(method, url, headers, &list.items)?;
    lines.push(format!(
        "\"@signature-params\": {}",
        serialize_inner_list(&list)
    ));
    let base = lines.join("\n").into_bytes();

    let bytes: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
        Error::new(
            Kind::SignatureMismatch,
            "An Ed25519 signature is 64 bytes; this one is not.",
        )
    })?;
    public
        .verify(&base, &Signature::from_bytes(&bytes))
        .map_err(|_| {
            Error::new(
                Kind::SignatureMismatch,
                "The signature does not match this request under the signer's key.",
            )
        })?;

    // AFTER the signature check, deliberately. created and expires are covered by the signature,
    // so acting on them before verifying it would enforce a policy against values an attacker
    // could still have chosen — and would tell that attacker their forgery at least parsed.
    check_freshness(&list, opts)?;

    if list.items.iter().any(|c| c == CONTENT_DIGEST) {
        check_digest(found.get(CONTENT_DIGEST), opts.body.as_deref())?;
    }
    Ok(Verdict {
        aid,
        covered: list.items,
    })
}

fn read(found: &BTreeMap<String, String>) -> Result<(InnerList, Vec<u8>)> {
    let raw_input = found
        .get("signature-input")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            Error::new(
                Kind::MissingSignatureInput,
                "This request has no Signature-Input header, so there is no way to know which \
             components a signature would cover.",
            )
        })?;
    let raw_signature = found
        .get("signature")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            Error::new(
                Kind::MissingSignature,
                "This request has no Signature header, so there is nothing to verify.",
            )
        })?;

    let inputs = parse_dictionary(raw_input).map_err(|_| {
        Error::new(
            Kind::MalformedSignatureInput,
            "I could not parse the Signature-Input header.",
        )
    })?;
    let signatures = parse_dictionary(raw_signature).map_err(|_| {
        Error::new(
            Kind::MalformedSignature,
            "I could not parse the Signature header.",
        )
    })?;

    if inputs.len() != 1 {
        return Err(Error::new(
            Kind::MalformedSignatureLabel,
            format!(
                "fiki verifies a request carrying exactly one signature; this one declares {}.",
                inputs.len()
            ),
        ));
    }
    let (label, input) = &inputs[0];
    let matching = signatures.iter().find(|(name, _)| name == label);
    let entry = match (matching, signatures.len()) {
        (Some((_, entry)), 1) => entry,
        _ => {
            return Err(Error::detailed(
                Kind::MissingSignatureLabel,
                format!("The Signature header carries no entry labelled {label}."),
                label,
            ))
        }
    };
    match &entry.value {
        Some(Value::Bytes(raw)) => Ok((input.list.clone(), raw.clone())),
        _ => Err(Error::new(
            Kind::MalformedSignatureValue,
            "RFC 9421 carries the signature as an RFC 8941 byte sequence, wrapped in colons.",
        )),
    }
}

fn resolve(expected_aid: Option<&str>, list: &InnerList) -> Result<String> {
    if let Some(aid) = expected_aid {
        return Ok(aid.to_string());
    }
    let keyid =
        match list.param("keyid") {
            Some(Value::Text(keyid)) if !keyid.is_empty() => keyid,
            _ => return Err(Error::new(
                Kind::MissingKey,
                "This signature carries no keyid and no expected_aid was supplied, so there is \
                 no key to verify it against.",
            )),
        };
    match decode(keyid, URL_ALPHABET) {
        Some(raw) if raw.len() == 32 => Ok(to_aid(&raw)),
        _ => Err(Error::detailed(
            Kind::MalformedKey,
            format!("The keyid {keyid} is not a base64url-encoded 32-byte Ed25519 public key."),
            keyid,
        )),
    }
}

fn check_freshness(list: &InnerList, opts: &VerifyOptions) -> Result<()> {
    let expires = match list.param("expires") {
        Some(Value::Integer(n)) => Some(*n),
        _ => None,
    };
    if expires.is_none() && opts.max_age.is_none() {
        return Ok(());
    }
    let skew = opts.skew.unwrap_or(DEFAULT_SKEW);
    let stamp = now_or(opts.now);

    if let Some(expires) = expires {
        if stamp > expires + skew {
            return Err(Error::new(
                Kind::SignatureExpired,
                format!(
                    "This signature expired at {expires} and it is now {stamp}, so the signer \
                     has already declared it should not be accepted."
                ),
            ));
        }
    }
    let Some(max_age) = opts.max_age else {
        return Ok(());
    };

    let created = match list.param("created") {
        Some(Value::Integer(n)) => *n,
        _ => {
            return Err(Error::new(
                Kind::SignatureTooOld,
                format!(
                    "This signature carries no created timestamp, so its age cannot be checked \
                     against the {max_age}-second limit you asked for."
                ),
            ))
        }
    };
    if stamp - created > max_age + skew {
        return Err(Error::new(
            Kind::SignatureTooOld,
            format!(
                "This signature was created at {created}, which is more than {max_age} seconds \
                 before {stamp}, so it is too old to accept."
            ),
        ));
    }
    if created - stamp > skew {
        return Err(Error::new(
            Kind::SignatureTooOld,
            format!(
                "This signature claims to have been created at {created}, which is in the future \
                 relative to {stamp} by more than the {skew}-second skew allowance."
            ),
        ));
    }
    Ok(())
}

fn check_digest(header: Option<&String>, body: Option<&[u8]>) -> Result<()> {
    // The header is covered by the signature, so it cannot have been tampered with — but a covered
    // digest still only attests to a body nobody hashed until somebody hashes it.
    let Some(body) = body else {
        return Err(Error::new(
            Kind::DigestMismatch,
            "The signature covers content-digest, but no body was supplied to check it against.",
        ));
    };
    let header = header.map(String::as_str).unwrap_or("");
    let parsed = parse_dictionary(header).map_err(|_| {
        Error::new(
            Kind::MalformedDigest,
            "I could not parse the Content-Digest header.",
        )
    })?;
    for (name, member) in &parsed {
        let computed = match name.to_ascii_lowercase().as_str() {
            "sha-256" => Sha256::digest(body).to_vec(),
            "sha-512" => Sha512::digest(body).to_vec(),
            _ => continue,
        };
        let Some(Value::Bytes(declared)) = &member.value else {
            return Err(Error::new(
                Kind::MalformedDigest,
                "A Content-Digest value is a byte sequence.",
            ));
        };
        if &computed != declared {
            return Err(Error::new(
                Kind::DigestMismatch,
                format!(
                    "The request body does not match its {name} Content-Digest, so the body is \
                     not the one that was signed."
                ),
            ));
        }
        return Ok(());
    }
    Err(Error::new(
        Kind::MalformedDigest,
        "The Content-Digest header names no algorithm fiki computes; it computes sha-256 and sha-512.",
    ))
}

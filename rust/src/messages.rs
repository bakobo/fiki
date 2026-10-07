//! Signing and verifying whole HTTP requests and responses (`this.i` @2hwvpm42, @7xrx5evg,
//! @67shl6c5, @7f28p7xk, @6g9zjsv9).
//!
//! The keyid is the signer's raw key unless the caller names another, such as a KERI AID, so "the
//! request carries its own verifying key" holds for every fiki-signed request whose caller did not
//! deliberately choose otherwise — and a verifier handed a resolver never falls back to reading a
//! key out of the keyid. A body is always covered or the signature is refused. And a verifier
//! states a freshness policy or explicitly declines one.
//!
//! The bound worth stating plainly: fiki cannot cover a body it was never given. The guarantee is
//! "hand fiki the body and it is covered, or fiki refuses" — a caller who omits it gets a valid
//! signature over a request whose body nothing protects, and no library can detect that.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

use crate::base::{
    base_for, canonical, canonical_request, check_covered, component, components, identity,
    lines_for, req, spec_of, Message, Request, SignatureParams, CONTENT_DIGEST, DEFAULT_COVERED,
};
use crate::errors::{Error, Kind, Result};
use crate::keys::{b64std, misspelled_aid, public_key, raw_keyid, to_aid, verifying_key, Key};
use crate::sfv::{parse_dictionary, serialize_inner_list, InnerList, Item, Member, Value};

/// The only signature algorithm fiki produces or accepts.
pub const ALG: &str = "ed25519";

/// Two hosts disagreeing by a second is ordinary; a verifier that treats it as an attack is
/// unusable.
pub const DEFAULT_SKEW: i64 = 5;

/// The KERI profile's minimum covered set for a request (its section 3), for
/// [`VerifyOptions::minimum`] and [`SignOptions::minimum`]. A body adds `content-digest` on top.
pub const REQUEST_MINIMUM: [&str; 3] = ["@method", "@path", "@query"];

/// The KERI profile's minimum covered set for a response. A body adds `content-digest`, and a
/// response to a request whose content was non-empty adds `"content-digest";req`.
pub const RESPONSE_MINIMUM: [&str; 4] = [
    "@status",
    "\"@method\";req",
    "\"@path\";req",
    "\"@query\";req",
];

const SIGNATURE_LENGTH: usize = 64;

/// Maps a keyid to the 32 raw bytes of the Ed25519 key it names, or `None` when it names no key
/// the caller knows (`this.i` @6g9zjsv9, @5e2phpjy).
///
/// Authoritative: fiki never falls back to decoding the keyid when one is supplied. It may refuse
/// a keyid itself — `MalformedKey` for one that is not a well-formed identifier, `UnsupportedSigner`
/// for a key state with no single key that satisfies its threshold — and fiki carries that refusal
/// out unchanged.
pub type Resolver = Arc<dyn Fn(&str) -> Result<Option<[u8; 32]>> + Send + Sync>;

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

fn has_content(body: Option<&[u8]>) -> bool {
    body.is_some_and(|b| !b.is_empty())
}

/// Everything about a signature beyond the message itself. The same options sign a request or a
/// response; `body` is the content of whichever is being signed.
#[derive(Debug, Default, Clone)]
pub struct SignOptions {
    pub body: Option<Vec<u8>>,
    /// `None` takes the default set. Naming your own is what turns a body without a digest from a
    /// helpful addition into a refusal. Each name is plain (`"@path"`) or serialized
    /// (`"\"@path\";req"`, which [`req`](crate::req) spells).
    pub covered: Option<Vec<String>>,
    pub created: Option<i64>,
    pub label: Option<String>,
    pub expires: Option<i64>,
    pub nonce: Option<String>,
    pub tag: Option<String>,
    /// The keyid to sign under, such as a KERI AID, which only a verifier with a resolver can
    /// check. `None` is the key itself, base64url (`this.i` @7xrx5evg).
    pub keyid: Option<String>,
    /// Refuse to sign a covered list the verifier would refuse, such as [`REQUEST_MINIMUM`]. A
    /// smaller set than the profile's is `InvalidArgument`.
    pub minimum: Option<Vec<String>>,
}

/// The outcome of a successful verification. An `Err` means it did not verify.
///
/// Carries no timestamp and asserts no freshness beyond the policy the caller stated. `aid` is the
/// non-transferable AID of the key that verified — or, when a resolver supplied that key, the keyid
/// the resolver vouched for. `covered` names each component as [`SignOptions::covered`] would
/// accept it, and `keyid` is the keyid as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub aid: String,
    pub covered: Vec<String>,
    pub keyid: Option<String>,
}

/// The verifier's policy and the body it has in hand.
///
/// `max_age` is an `Option<i64>` that the caller must fill in one way or the other: seconds of
/// tolerance, or an explicit `None` to decline the check. Both defaults would be wrong
/// (`this.i` @67shl6c5).
///
/// `expected_aid` and `resolve` each decide the key alone; supplying both is `InvalidArgument`.
/// `minimum` is the verifier's covered-set policy, [`REQUEST_MINIMUM`] or [`RESPONSE_MINIMUM`] or
/// a superset of it, which also requires `created` and applies the profile's body rule (`None`
/// applies no minimum at all). `expected_keyid` refuses a signature by any other keyid as
/// `UnknownKey`. `authorities` is the set of `@authority` values this verifier serves; a request
/// covering another is a `SignatureMismatch`.
#[derive(Default, Clone)]
pub struct VerifyOptions {
    pub max_age: Option<i64>,
    pub body: Option<Vec<u8>>,
    pub expected_aid: Option<String>,
    pub skew: Option<i64>,
    pub now: Option<i64>,
    pub resolve: Option<Resolver>,
    pub minimum: Option<Vec<String>>,
    pub expected_keyid: Option<String>,
    pub authorities: Option<BTreeSet<String>>,
}

impl fmt::Debug for VerifyOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyOptions")
            .field("max_age", &self.max_age)
            .field("body", &self.body)
            .field("expected_aid", &self.expected_aid)
            .field("skew", &self.skew)
            .field("now", &self.now)
            .field("resolve", &self.resolve.as_ref().map(|_| "<resolver>"))
            .field("minimum", &self.minimum)
            .field("expected_keyid", &self.expected_keyid)
            .field("authorities", &self.authorities)
            .finish()
    }
}

/// A supplied minimum selects the KERI profile's policy, so it may only add to the profile's.
/// Anything smaller is the caller's mistake rather than a message's defect, so it is
/// `InvalidArgument`, raised before any message is read.
fn floored(minimum: Option<&[String]>, floor: &[&str]) -> Result<Option<Vec<Item>>> {
    let Some(minimum) = minimum else {
        return Ok(None);
    };
    let given = components(minimum)?;
    let have: Vec<_> = given.iter().map(identity).collect();
    let mut missing = Vec::new();
    for spec in floor {
        if !have.contains(&identity(&component(spec)?)) {
            missing.push(*spec);
        }
    }
    if !missing.is_empty() {
        return Err(Error::new(
            Kind::InvalidArgument,
            format!(
                "A minimum covered set must include the profile's own, {}; this one leaves out {}. \
                 Pass None to apply no minimum at all.",
                floor.join(", "),
                missing.join(", ")
            ),
        ));
    }
    Ok(Some(given))
}

fn binds_request_digest(items: &[Item]) -> bool {
    items
        .iter()
        .any(|item| identity(item) == (CONTENT_DIGEST.to_string(), ";req".to_string()))
}

fn covers_body(items: &[Item]) -> bool {
    items.iter().any(|item| {
        let (name, params) = identity(item);
        name == CONTENT_DIGEST && params.is_empty()
    })
}

/// Cover a body the caller handed over, or refuse to sign (`this.i` @2hwvpm42).
fn cover_body(
    items: &mut Vec<Item>,
    sending: &mut BTreeMap<String, String>,
    body: Option<&[u8]>,
    chosen: bool,
) -> Result<()> {
    let Some(body) = body else {
        return Ok(());
    };
    // Whether the caller CHOSE the covered set is the difference between fiki helping and fiki
    // overriding. On the default path a body simply gets covered; on an explicit path, silently
    // adding a component would mean the signature covers something the caller did not ask for.
    if !covers_body(items) {
        if chosen {
            return Err(Error::new(
                Kind::UncoveredBody,
                "This message carries a body, but the covered components do not include \
                 \"content-digest\", so the signature would not bind the body. Add it to the \
                 covered set, or omit the body if it is genuinely not part of what you are signing.",
            ));
        }
        items.push(component(CONTENT_DIGEST)?);
    }
    if !sending
        .keys()
        .any(|name| name.eq_ignore_ascii_case(CONTENT_DIGEST))
    {
        sending.insert("Content-Digest".into(), content_digest(body));
    }
    Ok(())
}

fn params_for(key: &Key, opts: &SignOptions) -> SignatureParams {
    SignatureParams {
        created: Some(opts.created.unwrap_or_else(|| now_or(None))),
        keyid: Some(opts.keyid.clone().unwrap_or_else(|| key.keyid())),
        alg: Some(ALG.into()),
        expires: opts.expires,
        nonce: opts.nonce.clone(),
        tag: opts.tag.clone(),
    }
}

fn signed(
    key: &Key,
    base: &[u8],
    opts: &SignOptions,
    sending: &BTreeMap<String, String>,
    given: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let signature = key.sign(base);
    let text = String::from_utf8_lossy(base);
    let marker = "\"@signature-params\": ";
    let rendered = &text[text.rfind(marker).map(|at| at + marker.len()).unwrap_or(0)..];
    let label = opts.label.as_deref().unwrap_or("sig");

    let mut out = BTreeMap::new();
    out.insert("Signature-Input".into(), format!("{label}={rendered}"));
    out.insert(
        "Signature".into(),
        format!("{label}=:{}:", b64std(&signature)),
    );
    if let Some(made) = sending.get("Content-Digest") {
        if !given
            .keys()
            .any(|name| name.eq_ignore_ascii_case(CONTENT_DIGEST))
        {
            out.insert("Content-Digest".into(), made.clone());
        }
    }
    out
}

/// Sign a request and return the headers to add to it.
///
/// With a body and no explicit `covered`, fiki computes a `Content-Digest`, returns it among the
/// headers, and covers it; with an explicit `covered` that omits `content-digest`, it refuses with
/// `UncoveredBody`. `method` is signed exactly as given (`this.i` @22g0xkr8), so pass it as it will
/// go on the wire.
pub fn sign_request(
    key: &Key,
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    opts: &SignOptions,
) -> Result<BTreeMap<String, String>> {
    let minimum = floored(opts.minimum.as_deref(), &REQUEST_MINIMUM)?;
    let headers = &canonical(headers)?;
    let mut sending = headers.clone();
    let chosen = opts.covered.is_some();
    let mut items = match &opts.covered {
        Some(covered) => components(covered)?,
        None => components(&DEFAULT_COVERED.map(String::from))?,
    };
    cover_body(&mut items, &mut sending, opts.body.as_deref(), chosen)?;
    if let Some(minimum) = &minimum {
        let has_body = request_has_body(&sending, opts.body.as_deref());
        check_minimum(&items, minimum, has_body, false)?;
    }
    let base = base_for(
        &items,
        &Message::request(method, url, &sending),
        false,
        &params_for(key, opts),
    )?;
    Ok(signed(key, &base, opts, &sending, headers))
}

/// Sign a response to `request` and return the headers to add to it (RFC 9421 section 2.4).
///
/// By default the signature covers `@status`, a `Content-Digest` of any body, and — when the
/// `request` it answers is given — that request's method, path and query, plus its
/// `content-digest` when it had content, each marked `req`. A request with content and no digest to
/// bind is refused as `UncoveredBody`, and a request digest the request's body contradicts is
/// refused the way the verifier would refuse it.
pub fn sign_response(
    key: &Key,
    status: u16,
    request: Option<&Request>,
    headers: &BTreeMap<String, String>,
    opts: &SignOptions,
) -> Result<BTreeMap<String, String>> {
    let minimum = floored(opts.minimum.as_deref(), &RESPONSE_MINIMUM)?;
    let headers = &canonical(headers)?;
    let asked = canonical_request(request)?;
    let request = asked.as_ref();
    let mut sending = headers.clone();
    let chosen = opts.covered.is_some();
    // By content alone: both sides hold the whole request by now (profile section 3, @7p9s3g9k).
    let had_body = request.is_some_and(|r| has_content(r.body.as_deref()));
    let covered = opts.covered.clone().unwrap_or_else(|| {
        let mut covered = vec!["@status".to_string()];
        if request.is_some() {
            covered.extend(["@method", "@path", "@query"].map(req));
        }
        covered
    });
    let mut items = components(&covered)?;
    cover_body(&mut items, &mut sending, opts.body.as_deref(), chosen)?;
    if let (false, true, Some(request)) = (chosen, had_body, request) {
        if !request.headers.contains_key(CONTENT_DIGEST) {
            return Err(Error::new(
                Kind::UncoveredBody,
                "The request this response answers carried a body and no Content-Digest, so the \
                 response has nothing to bind that body with. Sign the request with a digest \
                 first, or name the covered components yourself.",
            ));
        }
        items.push(component(&req(CONTENT_DIGEST))?);
    }
    if let Some(minimum) = &minimum {
        check_minimum(&items, minimum, has_content(opts.body.as_deref()), had_body)?;
    }
    // The check verify_response will make, made first: a signer does not vouch for a request
    // digest that the request body it was handed contradicts (bakobo/fiki#4).
    if let Some(Request {
        headers: asked,
        body: Some(content),
        ..
    }) = request
    {
        if binds_request_digest(&items) {
            let recognized = read_digest(asked.get(CONTENT_DIGEST))?;
            compare_digest(&recognized, Some(content))?;
        }
    }
    let base = base_for(
        &items,
        &Message::response(status, &sending, request),
        true,
        &params_for(key, opts),
    )?;
    Ok(signed(key, &base, opts, &sending, headers))
}

/// Verify a signed request, in the KERI profile's section 9 order so a message has exactly one
/// correct refusal.
pub fn verify_request(
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    opts: &VerifyOptions,
) -> Result<Verdict> {
    let minimum = floored(opts.minimum.as_deref(), &REQUEST_MINIMUM)?;
    let headers = &canonical(headers)?;
    verify(
        &Message::request(method, url, headers),
        headers,
        None,
        opts,
        minimum,
    )
}

/// Verify a signed response to `request`, whose `req` components are read from it.
///
/// An unsigned 401 is `Unauthenticated`, checked before anything else in the message, because a
/// server that refuses before it knows the agent cannot sign the refusal. A response's body is its
/// content, never its `Content-Length`, so a HEAD or 304 response is bodiless whatever length it
/// announces. A client should pass `expected_keyid`, the AID it is talking to. A response covering
/// `"content-digest";req` verified against a `request` whose body is `None` is `InvalidArgument`:
/// that digest is recomputed over the request body, and fiki cannot check a body it was not given.
/// So is `authorities`, which a response has no use for.
pub fn verify_response(
    status: u16,
    headers: &BTreeMap<String, String>,
    request: Option<&Request>,
    opts: &VerifyOptions,
) -> Result<Verdict> {
    let minimum = floored(opts.minimum.as_deref(), &RESPONSE_MINIMUM)?;
    if opts.authorities.is_some() {
        return Err(Error::new(
            Kind::InvalidArgument,
            "A response has no @authority of its own, so served authorities do not apply to one; \
             pass authorities when verifying the request.",
        ));
    }
    let headers = &canonical(headers)?;
    let asked = canonical_request(request)?;
    let request = asked.as_ref();
    if status == 401 && !headers.contains_key("signature") {
        return Err(Error::new(
            Kind::Unauthenticated,
            "The server answered 401 without signing the answer, so the request was not \
             authenticated and the body of the refusal cannot be trusted.",
        ));
    }
    verify(
        &Message::response(status, headers, request),
        headers,
        Some(request),
        opts,
        minimum,
    )
}

/// The KERI profile's section 9 order. `response` is `Some` for a response, holding the request it
/// answers if there is one.
fn verify(
    message: &Message,
    headers: &BTreeMap<String, String>,
    response: Option<Option<&Request>>,
    opts: &VerifyOptions,
    minimum: Option<Vec<Item>>,
) -> Result<Verdict> {
    if opts.expected_aid.is_some() && opts.resolve.is_some() {
        return Err(Error::new(
            Kind::InvalidArgument,
            "Pass expected_aid or resolve, not both; each decides the key alone.",
        ));
    }
    let request = response.flatten();
    let found = headers;
    let (inner, signature) = read(found, opts.expected_aid.is_none(), minimum.is_some())?;
    let items = &inner.items;
    check_covered(items, response.is_some())?;
    if let Some(minimum) = &minimum {
        let has_body = match response {
            Some(_) => has_content(opts.body.as_deref()),
            None => request_has_body(found, opts.body.as_deref()),
        };
        // By the request's content alone, as sign_response decides it (@7p9s3g9k).
        let request_had_body = request.is_some_and(|r| has_content(r.body.as_deref()));
        check_minimum(items, minimum, has_body, request_had_body)?;
    }

    let keyid = match inner.param("keyid") {
        Some(Value::Text(keyid)) => Some(keyid.clone()),
        _ => None,
    };
    if let Some(expected) = &opts.expected_keyid {
        if keyid.as_ref() != Some(expected) {
            let shown = keyid.clone().unwrap_or_default();
            return Err(Error::detailed(
                Kind::UnknownKey,
                format!("This message is signed by \"{shown}\", and the one expected is \"{expected}\"."),
                shown,
            ));
        }
    }
    let (public, aid) = resolve(opts, keyid.as_deref())?;
    if let Some(Value::Text(alg)) = inner.param("alg") {
        if alg != ALG {
            return Err(Error::detailed(
                Kind::UnsupportedAlgorithm,
                format!("This signature is made with \"{alg}\", and fiki verifies only {ALG}."),
                alg,
            ));
        }
    }

    let mut lines = lines_for(items, message)?;
    lines.push(format!(
        "\"@signature-params\": {}",
        serialize_inner_list(&inner)
    ));
    public
        .verify(
            lines.join("\n").as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| {
            Error::new(
                Kind::SignatureMismatch,
                "The signature does not match this message under the signer's key, so the \
                 message cannot be treated as authentic.",
            )
        })?;

    if let Some(served) = &opts.authorities {
        for item in items.iter().filter(|i| i.text() == Some("@authority")) {
            let value = crate::base::value_of(item, message)?;
            if !served.contains(&value) {
                return Err(Error::detailed(
                    Kind::SignatureMismatch,
                    format!(
                        "The signature covers the authority \"{value}\", which this verifier \
                         does not serve, so it was signed for somebody else."
                    ),
                    value,
                ));
            }
        }
    }

    // AFTER the signature check, deliberately. created and expires are covered by the signature,
    // so acting on them before verifying it would enforce a policy against values an attacker
    // could still have chosen — and would tell that attacker their forgery at least parsed.
    check_freshness(&inner, opts)?;

    let mut digests = Vec::new();
    if covers_body(items) {
        digests.push((found.get(CONTENT_DIGEST), opts.body.as_deref()));
    }
    // A response binding the request's digest binds a request body only if somebody hashes it. A
    // verifier handed no request body cannot, and a verdict that skipped the check would look like
    // one that made it, so that is the caller's mistake, not a pass.
    let asked = request.map(|r| &r.headers);
    if let (Some(request), Some(asked)) = (request, &asked) {
        if binds_request_digest(items) {
            let Some(content) = request.body.as_deref() else {
                return Err(Error::new(
                    Kind::InvalidArgument,
                    "The response covers \"content-digest\";req, so the request body it binds \
                     must be supplied in Request::body to be checked; it was not.",
                ));
            };
            digests.push((asked.get(CONTENT_DIGEST), Some(content)));
        }
    }
    // Every covered digest is parsed before any is compared, so a malformed one outranks a
    // mismatched one wherever each sits (profile section 9).
    let parsed = digests
        .into_iter()
        .map(|(header, content)| Ok((read_digest(header)?, content)))
        .collect::<Result<Vec<_>>>()?;
    for (recognized, content) in &parsed {
        compare_digest(recognized, *content)?;
    }

    Ok(Verdict {
        aid,
        covered: items.iter().map(spec_of).collect(),
        keyid,
    })
}

/// The profile's request body test: a length above zero, any transfer coding, or content.
///
/// Requests only. A response's body is its content, since a HEAD or 304 response carries the
/// length of a representation it does not send.
fn request_has_body(found: &BTreeMap<String, String>, body: Option<&[u8]>) -> bool {
    if has_content(body) || found.contains_key("transfer-encoding") {
        return true;
    }
    match found.get("content-length").map(|l| l.trim()) {
        None => false,
        // Fail closed: a length that is not a plain decimal, negative ones included, is not
        // evidence that there is no body.
        Some(length) => {
            length.is_empty()
                || !length.bytes().all(|b| b.is_ascii_digit())
                || length.bytes().any(|b| b != b'0')
        }
    }
}

fn check_minimum(
    items: &[Item],
    minimum: &[Item],
    has_body: bool,
    request_had_body: bool,
) -> Result<()> {
    let have: Vec<_> = items.iter().map(identity).collect();
    let mut required = minimum.to_vec();
    if has_body {
        required.push(component(CONTENT_DIGEST)?);
    }
    if request_had_body {
        required.push(component(&req(CONTENT_DIGEST))?);
    }
    match required.iter().find(|item| !have.contains(&identity(item))) {
        None => Ok(()),
        Some(item) => Err(Error::detailed(
            Kind::InsufficientCoverage,
            format!(
                "The signature does not cover {}, which this verifier requires, so it is refused \
                 even though it may be valid: a signature over too little is a signature over what \
                 an intermediary is free to change.",
                spec_of(item)
            ),
            spec_of(item),
        )),
    }
}

/// Pull one signature and its input out of the headers, or say what is wrong with them: absence
/// before malformation, the Signature header before Signature-Input, the members' shape before the
/// label count.
fn read(
    found: &BTreeMap<String, String>,
    require_keyid: bool,
    require_created: bool,
) -> Result<(InnerList, [u8; SIGNATURE_LENGTH])> {
    let present = |name: &str| found.get(name).filter(|v| !v.is_empty());
    let raw_signature = present("signature").ok_or_else(|| {
        Error::new(
            Kind::MissingSignature,
            "This message has no Signature header, so there is nothing to verify.",
        )
    })?;
    let raw_input = present("signature-input").ok_or_else(|| {
        Error::new(
            Kind::MissingSignatureInput,
            "This message has no Signature-Input header, so there is no way to know which \
             components a signature would cover.",
        )
    })?;

    let signatures = parse_dictionary(raw_signature).map_err(|_| {
        Error::new(
            Kind::MalformedSignature,
            "I could not parse the Signature header; RFC 9421 spells it as an RFC 8941 dictionary.",
        )
    })?;
    let mut values = Vec::new();
    for (label, member) in &signatures {
        match member {
            Member::Item(Item {
                value: Value::Bytes(raw),
                ..
            }) => values.push((label, raw)),
            _ => {
                return Err(Error::new(
                    Kind::MalformedSignatureValue,
                    "RFC 9421 carries a signature as an RFC 8941 byte sequence, wrapped in \
                     colons; this Signature header carries something else.",
                ))
            }
        }
    }
    let inputs = parse_dictionary(raw_input).map_err(|_| {
        Error::new(
            Kind::MalformedSignatureInput,
            "I could not parse the Signature-Input header; RFC 9421 spells it as an RFC 8941 \
             dictionary.",
        )
    })?;
    let mut lists = Vec::new();
    for (label, member) in &inputs {
        lists.push((label, check_input(member, require_keyid, require_created)?));
    }

    if lists.len() != 1 || values.len() != 1 {
        return Err(Error::new(
            Kind::MalformedSignatureLabel,
            format!(
                "fiki verifies a message carrying exactly one signature; this one declares {} in \
                 Signature-Input and {} in Signature.",
                lists.len(),
                values.len()
            ),
        ));
    }
    let (label, list) = lists.remove(0);
    let Some((_, value)) = values.into_iter().find(|(name, _)| *name == label) else {
        return Err(Error::detailed(
            Kind::MissingSignatureLabel,
            format!(
                "The Signature header carries no entry labelled \"{label}\", so the covered \
                 components describe a signature that is not here."
            ),
            label,
        ));
    };
    let value: [u8; SIGNATURE_LENGTH] = value.as_slice().try_into().map_err(|_| {
        Error::new(
            Kind::MalformedSignatureValue,
            "RFC 9421 carries an Ed25519 signature as a 64-byte RFC 8941 byte sequence, wrapped in \
             colons; this one is something else.",
        )
    })?;
    Ok((list.clone(), value))
}

/// Refuse a Signature-Input member fiki would otherwise have to guess about.
fn check_input(member: &Member, require_keyid: bool, require_created: bool) -> Result<&InnerList> {
    let malformed = |why: String| Err(Error::new(Kind::MalformedSignatureInput, why));
    let Member::List(list) = member else {
        return malformed(
            "A Signature-Input member is a parenthesized list of covered components; this one is \
             a single value."
                .into(),
        );
    };
    for item in &list.items {
        let Some(name) = item.text() else {
            return malformed(format!(
                "Every covered component is named by a quoted string; {} is not one.",
                crate::sfv::serialize_item(item)
            ));
        };
        if !name.starts_with('@') && name != name.to_ascii_lowercase() {
            return malformed(format!(
                "The covered field \"{name}\" is not lowercase, and RFC 9421 section 2.1 requires \
                 field names in the covered list to be lowercased by the signer."
            ));
        }
    }
    if require_keyid && list.param("keyid").is_none() {
        // Here rather than when the key is resolved: keyid is REQUIRED, so its absence belongs
        // with the other defects of Signature-Input, ahead of the covered list.
        return Err(Error::new(
            Kind::MissingKey,
            "This signature carries no keyid and no expected_aid was supplied, so there is no key \
             to verify it against.",
        ));
    }
    if require_created && list.param("keyid").is_none() {
        // Under a minimum, which is how a caller applies the KERI profile, keyid is REQUIRED even
        // when expected_aid names the key, as created is below (@5xde8s6l).
        return malformed(
            "This signature carries no keyid, which the verifier's policy requires.".into(),
        );
    }
    if require_created && list.param("created").is_none() {
        // Only under a minimum, which is how a caller applies the KERI profile, where created is
        // REQUIRED. RFC 9421 makes it optional, and without a minimum it stays so (@7p9s3g9k).
        return malformed(
            "This signature carries no created timestamp, which the verifier's policy requires."
                .into(),
        );
    }
    for (name, value) in &list.params {
        let integer = match name.as_str() {
            "created" | "expires" => true,
            "nonce" | "alg" | "keyid" | "tag" => false,
            _ => {
                return malformed(format!(
                    "The signature parameter \"{name}\" is not one fiki understands; it accepts \
                     created, expires, nonce, alg, keyid, tag."
                ))
            }
        };
        let fits = match value {
            Value::Integer(_) => integer,
            Value::Text(_) => !integer,
            _ => false,
        };
        if !fits {
            return malformed(format!(
                "The signature parameter \"{name}\" must be {}.",
                if integer {
                    "an integer"
                } else {
                    "a quoted string"
                }
            ));
        }
    }
    Ok(list)
}

/// The key to verify with and the identity to report.
fn resolve(opts: &VerifyOptions, keyid: Option<&str>) -> Result<(VerifyingKey, String)> {
    if let Some(aid) = &opts.expected_aid {
        let public = verifying_key(aid)?;
        return Ok((public, to_aid(public.as_bytes())));
    }
    let keyid = keyid.filter(|k| !k.is_empty()).ok_or_else(|| {
        Error::new(
            Kind::MissingKey,
            "This signature carries no keyid and no expected_aid was supplied, so there is no key \
             to verify it against.",
        )
    })?;
    let malformed = |why: String| Error::detailed(Kind::MalformedKey, why, keyid);
    if let Some(resolver) = &opts.resolve {
        if misspelled_aid(keyid) {
            return Err(malformed(format!(
                "The keyid \"{keyid}\" is shaped like an AID and is not its canonical spelling, so \
                 it is not an AID at all."
            )));
        }
        // The resolver is authoritative: fiki never falls back to decoding the keyid, because a
        // transferable prefix that embeds a key embeds its INCEPTION key (@6g9zjsv9).
        let raw = resolver(keyid)?.ok_or_else(|| {
            Error::detailed(
                Kind::UnknownKey,
                format!(
                    "No key is known for the keyid \"{keyid}\", so the signature cannot be checked."
                ),
                keyid,
            )
        })?;
        let public = public_key(&raw).ok_or_else(|| {
            malformed(format!(
                "The key resolved for \"{keyid}\" is not a usable Ed25519 public key: it is not a \
                 point on the curve, or it is a small-order point, under which a signature proves \
                 nothing."
            ))
        })?;
        return Ok((public, keyid.to_string()));
    }
    let raw = raw_keyid(keyid).ok_or_else(|| {
        malformed(format!(
            "The keyid \"{keyid}\" is not a base64url-encoded 32-byte Ed25519 public key: that is \
             exactly 43 characters from the base64url alphabet, unpadded, in the key's own \
             spelling."
        ))
    })?;
    let public = public_key(&raw).ok_or_else(|| {
        malformed(format!(
            "The keyid \"{keyid}\" is not a usable Ed25519 public key: it is not a point on the \
             curve, or it is a small-order point, under which a signature proves nothing."
        ))
    })?;
    Ok((public, to_aid(&raw)))
}

/// Enforce the verifier's `max_age`, then the signer's `expires` (profile section 9).
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

    if let Some(max_age) = opts.max_age {
        let too_old = |why: String| Err(Error::new(Kind::SignatureTooOld, why));
        let Some(Value::Integer(created)) = list.param("created") else {
            return too_old(format!(
                "This signature carries no created timestamp, so its age cannot be checked against \
                 the {max_age}-second limit you asked for."
            ));
        };
        if stamp - created > max_age + skew {
            return too_old(format!(
                "This signature was created at {created}, which is more than {max_age} seconds \
                 before {stamp}, so it is too old to accept."
            ));
        }
        if created - stamp > skew {
            return too_old(format!(
                "This signature claims to have been created at {created}, which is in the future \
                 relative to {stamp} by more than the {skew}-second skew allowance."
            ));
        }
    }
    match expires {
        Some(expires) if stamp > expires + skew => Err(Error::new(
            Kind::SignatureExpired,
            format!(
                "This signature expired at {expires} and it is now {stamp}, so the signer has \
                 already declared it should not be accepted."
            ),
        )),
        _ => Ok(()),
    }
}

type Recognized = Vec<(&'static str, Vec<u8>)>;

/// Parse a Content-Digest into the members fiki computes, or refuse it as `MalformedDigest`.
///
/// Separate from the comparison so that a verifier holding two covered digests can parse both
/// before hashing either: section 9 of the KERI profile puts malformed-digest first. sha-256 and
/// sha-512 are recognized, because fiki is not the only thing that will ever have signed a message
/// it is asked to verify; any other algorithm is ignored (RFC 9530 section 2).
fn read_digest(header: Option<&String>) -> Result<Recognized> {
    let malformed = |why: &str| Error::new(Kind::MalformedDigest, why.to_string());
    let parsed = header
        .and_then(|h| parse_dictionary(h).ok())
        .ok_or_else(|| {
            malformed("I could not parse the Content-Digest header; RFC 9530 spells it as an RFC 8941 dictionary.")
        })?;
    let mut recognized = Vec::new();
    for (name, member) in &parsed {
        let algorithm = match name.as_str() {
            "sha-256" => "sha-256",
            "sha-512" => "sha-512",
            _ => continue,
        };
        let Member::Item(Item {
            value: Value::Bytes(expected),
            ..
        }) = member
        else {
            return Err(malformed(&format!(
                "The {name} Content-Digest is not an RFC 8941 byte sequence, so it cannot be \
                 compared with anything."
            )));
        };
        recognized.push((algorithm, expected.clone()));
    }
    if recognized.is_empty() {
        return Err(malformed(
            "The Content-Digest header names no algorithm fiki computes; it computes sha-256 and \
             sha-512.",
        ));
    }
    Ok(recognized)
}

/// Every recognized member must match the body actually received (`this.i` @2hwvpm42). The header
/// is covered by the signature, so it cannot have been tampered with — but a covered digest still
/// only attests to a body nobody hashed until somebody hashes it.
fn compare_digest(recognized: &Recognized, body: Option<&[u8]>) -> Result<()> {
    let Some(body) = body else {
        return Err(Error::new(
            Kind::DigestMismatch,
            "The signature covers content-digest, but no body was supplied to check it against, \
             so the body is unverified.",
        ));
    };
    for (name, expected) in recognized {
        let computed = match *name {
            "sha-256" => Sha256::digest(body).to_vec(),
            _ => Sha512::digest(body).to_vec(),
        };
        if &computed != expected {
            return Err(Error::new(
                Kind::DigestMismatch,
                format!(
                    "The body does not match its {name} Content-Digest, so the body is not the one \
                     that was signed."
                ),
            ));
        }
    }
    Ok(())
}

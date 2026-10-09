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
    base_for, brief, canonical, canonical_request, check_covered, check_label, component,
    components, identity, lines_for, req, shown, spec_of, Asked, Message, Request, SignatureParams,
    CONTENT_DIGEST, DEFAULT_COVERED, MAX_FIELD_BYTES,
};
use crate::errors::{Error, Kind, Result};
use crate::keys::{aid_of, b64std, misspelled_aid, public_key, raw_keyid, verifying_key, Key};
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

/// What [`verify_request`] requires when the caller states no minimum of its own
/// ([`Minimum::Default`], `this.i` @524c8qgv): fiki's own signing default, so a verifier left at
/// its defaults accepts what a fiki signer produces and nothing that covers less. A body adds
/// `content-digest`, and, being a minimum, it requires `created` and a `keyid`.
pub const DEFAULT_MINIMUM: [&str; 4] = ["@method", "@authority", "@path", "@query"];

/// The verifier's covered-set policy, [`VerifyOptions::minimum`].
///
/// Three states rather than an `Option`, because "not stated" and "opted out" must differ: left
/// at [`Minimum::Default`], [`verify_request`] applies [`DEFAULT_MINIMUM`] and [`verify_response`]
/// applies [`RESPONSE_MINIMUM`] (`this.i` @524c8qgv), and only [`Minimum::Off`] applies none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Minimum {
    /// Not stated: [`DEFAULT_MINIMUM`] for a request, [`RESPONSE_MINIMUM`] for a response.
    #[default]
    Default,
    /// The explicit opt-out: no minimum, and so no body rule and no required `created`. A body
    /// handed over with no covered `content-digest` is accepted, and the verdict's `covered` is the
    /// only place that shows it (@2f227n4r).
    Off,
    /// This minimum, which must include [`REQUEST_MINIMUM`] or [`RESPONSE_MINIMUM`]; anything
    /// smaller is `InvalidArgument`.
    Of(Vec<String>),
}

impl Minimum {
    /// This minimum: `Minimum::of(REQUEST_MINIMUM)`, or any collection of component names.
    pub fn of<I, S>(components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Minimum::Of(components.into_iter().map(Into::into).collect())
    }
}

/// The age a verifier tolerates, [`VerifyOptions::max_age`] (`this.i` @67shl6c5, @65u2932c).
///
/// A required decision with no default, as [`Authorities`] is: a tolerance in seconds, or the
/// explicit decision not to check age. Both defaults would be wrong — a value guesses at somebody
/// else's clock skew and replay window, and declining by default is the silent skip the field
/// exists to prevent — so [`verify_request`] and [`verify_response`] refuse
/// [`MaxAge::Unstated`] as `InvalidArgument`, and `..Default::default()` does not decide it.
/// Declining the age check never declines the signer's `expires`, which is always enforced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MaxAge {
    /// No decision was made, which [`verify_request`] and [`verify_response`] refuse as
    /// `InvalidArgument`.
    #[default]
    Unstated,
    /// The explicit decision not to check how old a signature is.
    Unchecked,
    /// A signature created more than this many seconds before now, beyond the skew allowance, is
    /// `SignatureTooOld`. Not positive is `InvalidArgument`.
    Seconds(i64),
}

impl MaxAge {
    /// A tolerance of `seconds`: `MaxAge::seconds(300)`.
    pub fn seconds(seconds: i64) -> Self {
        MaxAge::Seconds(seconds)
    }

    fn seconds_or_none(self) -> Option<i64> {
        match self {
            MaxAge::Seconds(seconds) => Some(seconds),
            _ => None,
        }
    }
}

/// The `@authority` values a verifier serves, [`VerifyOptions::authorities`] (`this.i` @524c8qgv).
///
/// [`verify_request`] has no default for it, as it has none for `max_age`: the caller decides, and
/// leaving it at [`Authorities::Unstated`] is `InvalidArgument`. Entries are compared exactly with
/// `@authority` as fiki derives it: a lowercase host, and a port unless it is the default port of
/// an absolute URL's scheme.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Authorities {
    /// No decision was made, which [`verify_request`] refuses as `InvalidArgument`.
    #[default]
    Unstated,
    /// The explicit decision not to check which host a request was signed for.
    Unchecked,
    /// The hosts this verifier serves. A covered `@authority` outside them is `SignatureMismatch`,
    /// and stating them makes `@authority` required even under [`Minimum::Off`] (@605z9tnw). An
    /// empty set serves no host at all, so it is `InvalidArgument`.
    Served(BTreeSet<String>),
}

impl Authorities {
    /// The hosts this verifier serves: `Authorities::served(["api.example.com"])`. A bare string
    /// is not a collection of hosts, so `served("api.example.com")` does not compile.
    pub fn served<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Authorities::Served(hosts.into_iter().map(Into::into).collect())
    }
}

/// The keyid a verifier expects, [`VerifyOptions::expected_keyid`] (`this.i` @524c8qgv).
///
/// [`verify_response`] has no default for it, as [`verify_request`] has none for `authorities`: a
/// client states the AID it believes it is talking to (profile R1), or explicitly declines the
/// check and reads the signer from the verdict. Left [`ExpectedKeyid::Unstated`], a response is
/// `InvalidArgument`; a request verifier, which has `expected_aid` and `resolve` to decide its
/// key, reads `Unstated` as `Unchecked`. An empty keyid names no AID, so `Is("")` is
/// `InvalidArgument` in both, never the decline.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ExpectedKeyid {
    /// No decision was made, which [`verify_response`] refuses as `InvalidArgument`.
    #[default]
    Unstated,
    /// The explicit decision to accept any signer, whose keyid the verdict carries.
    Unchecked,
    /// The keyid the signature must carry; any other is `UnknownKey`.
    Is(String),
}

impl ExpectedKeyid {
    /// The keyid the signature must carry: `ExpectedKeyid::is(aid)`.
    pub fn is(keyid: impl Into<String>) -> Self {
        ExpectedKeyid::Is(keyid.into())
    }
}

const SIGNATURE_LENGTH: usize = 64;

// MAX_FIELD_BYTES, in base, bounds the Signature, Signature-Input and Content-Digest headers too,
// measured before each is parsed (`this.i` @5zrf8gjk, ticks 65q7 and 6mhg). Over it, or any limit
// below, is that header's malformed kind. They are far above anything an honest signer sends and
// low enough that no parse is slow.

/// The most members fiki reads in any of those three dictionaries.
pub const MAX_DICTIONARY_MEMBERS: usize = 16;

/// The most items fiki reads in any inner list of those three headers, such as a covered list.
pub const MAX_INNER_LIST_ITEMS: usize = 64;

/// The most parameters fiki reads on any item or inner list of those three headers.
pub const MAX_PARAMETERS: usize = 16;

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
/// identity that vouched for the key: the non-transferable AID of a raw key, or the keyid a
/// resolver vouched for (`this.i` @6g9zjsv9), or the AID of `expected_aid`. `keyid` is the keyid
/// exactly as it appeared on the wire, or `None` when the signature had none (@5zrf8gjk), so a
/// verifier given `expected_aid` can still see what the signer claimed. `covered` names each
/// component as [`SignOptions::covered`] would accept it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub aid: String,
    pub covered: Vec<String>,
    pub keyid: Option<String>,
}

/// The verifier's policy and the body it has in hand.
///
/// `max_age` is a required decision ([`MaxAge`]): [`MaxAge::seconds`] of tolerance, or
/// [`MaxAge::Unchecked`] to decline the check. Left [`MaxAge::Unstated`] it is `InvalidArgument`
/// in both [`verify_request`] and [`verify_response`], because both defaults would be wrong
/// (`this.i` @67shl6c5, @65u2932c).
///
/// `authorities` is a decision of the same kind for [`verify_request`] (`this.i` @524c8qgv): the
/// hosts this verifier serves, or [`Authorities::Unchecked`]; left [`Authorities::Unstated`] it is
/// `InvalidArgument`. A request covering a host outside them is a `SignatureMismatch`, and stating
/// them makes `@authority` required, so a request that does not cover it is `InsufficientCoverage`
/// (@605z9tnw).
///
/// `expected_aid` and `resolve` each decide the key alone; supplying both is `InvalidArgument`.
/// `minimum` is the verifier's covered-set policy ([`Minimum`]): left at its default a request
/// must cover [`DEFAULT_MINIMUM`]; a stated one is [`REQUEST_MINIMUM`] or [`RESPONSE_MINIMUM`] or
/// a superset of it. Any minimum also requires `created`, a `keyid` even beside `expected_aid`,
/// and applies the profile's body rule; [`Minimum::Off`] applies none of it. `expected_keyid`
/// ([`ExpectedKeyid`]) refuses a signature by any other keyid as `UnknownKey`, and is a required
/// decision for [`verify_response`].
#[derive(Default, Clone)]
pub struct VerifyOptions {
    pub max_age: MaxAge,
    pub body: Option<Vec<u8>>,
    pub expected_aid: Option<String>,
    pub skew: Option<i64>,
    pub now: Option<i64>,
    pub resolve: Option<Resolver>,
    pub minimum: Minimum,
    pub expected_keyid: ExpectedKeyid,
    pub authorities: Authorities,
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

/// A verifier's [`Minimum`] as the minimum it applies, `default` standing in when none is stated.
fn stated(
    minimum: &Minimum,
    default: Option<&[&str]>,
    floor: &[&str],
) -> Result<Option<Vec<Item>>> {
    match minimum {
        Minimum::Default => {
            let default = default.map(|d| d.iter().map(|s| s.to_string()).collect::<Vec<_>>());
            floored(default.as_deref(), floor)
        }
        Minimum::Off => Ok(None),
        Minimum::Of(given) => floored(Some(given), floor),
    }
}

/// `expected_keyid` is a decision the caller made where it is required, and never an empty keyid
/// (`this.i` @524c8qgv, part-two refinements): "" names no AID, and reading it as the decline would
/// turn a caller's missing value into "accept any signer".
fn check_expected_keyid(expected: &ExpectedKeyid, required: bool) -> Result<()> {
    match expected {
        ExpectedKeyid::Unstated if required => Err(Error::new(
            Kind::InvalidArgument,
            "expected_keyid is a required decision: state the AID this client is talking to, \
             such as ExpectedKeyid::is(aid), or ExpectedKeyid::Unchecked to accept any signer and \
             read it from the verdict.",
        )),
        ExpectedKeyid::Is(keyid) if keyid.is_empty() => Err(Error::new(
            Kind::InvalidArgument,
            "expected_keyid is empty, which names no AID; pass ExpectedKeyid::Unchecked to accept \
             any signer and read it from the verdict.",
        )),
        _ => Ok(()),
    }
}

/// `authorities` is a decision the caller made, and a set of hosts is not empty (@524c8qgv).
fn check_authorities(authorities: &Authorities) -> Result<()> {
    match authorities {
        Authorities::Unstated => Err(Error::new(
            Kind::InvalidArgument,
            "authorities is a required decision: state the hosts this verifier serves, such as \
             Authorities::served([\"api.example.com\"]), or Authorities::Unchecked to decline the \
             check.",
        )),
        Authorities::Served(hosts) if hosts.is_empty() => Err(Error::new(
            Kind::InvalidArgument,
            "authorities is empty, which serves no host at all; pass Authorities::Unchecked to \
             decline the check.",
        )),
        _ => Ok(()),
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
                 State no minimum to take the default, or opt out of any.",
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
    if let Some(given) = sending.get(CONTENT_DIGEST) {
        // A digest the caller supplied is signed as given, so it must be one the verifier will
        // accept for this body: anything else is the call's mistake, not a message (@5zrf8gjk).
        read_digest(Some(given))
            .and_then(|recognized| compare_digest(&recognized, Some(body)))
            .map_err(|refused| {
                Error::new(
                    Kind::InvalidArgument,
                    format!(
                        "The Content-Digest supplied with this body is not one a verifier would \
                         accept for it: {refused} Omit it and fiki computes one, or supply the \
                         body it describes."
                    ),
                )
            })?;
    }
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
    // `sending` is canonical, so its names are lowercase already.
    sending
        .entry(CONTENT_DIGEST.into())
        .or_insert_with(|| content_digest(body));
    Ok(())
}

fn label_of(opts: &SignOptions) -> &str {
    opts.label.as_deref().unwrap_or("sig")
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
    let label = label_of(opts);

    let mut out = BTreeMap::new();
    out.insert("Signature-Input".into(), format!("{label}={rendered}"));
    out.insert(
        "Signature".into(),
        format!("{label}=:{}:", b64std(&signature)),
    );
    if let Some(made) = sending.get(CONTENT_DIGEST) {
        if !given.contains_key(CONTENT_DIGEST) {
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
///
/// Mistakes in the call are `InvalidArgument`, never another kind (`this.i` @5zrf8gjk): a method
/// that is not an HTTP token, a URL whose port is not a number from 0 to 65535, a label that is not
/// an RFC 8941 key, a keyid, nonce or tag outside printable ASCII, a component name that is not a
/// field name, a `created` or `expires` outside 0 to 999999999999999, and a supplied
/// `Content-Digest` that is unreadable or that the body does not match.
pub fn sign_request(
    key: &Key,
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    opts: &SignOptions,
) -> Result<BTreeMap<String, String>> {
    check_label(label_of(opts))?;
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
        &Message::request(method, url, &sending, false)?,
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
    check_label(label_of(opts))?;
    let minimum = floored(opts.minimum.as_deref(), &RESPONSE_MINIMUM)?;
    let headers = &canonical(headers)?;
    let asked = canonical_request(request)?;
    let request = asked.as_ref();
    let mut sending = headers.clone();
    let chosen = opts.covered.is_some();
    // By content alone: both sides hold the whole request by now (profile section 3, @7p9s3g9k).
    let had_body = request.is_some_and(|r| has_content(r.body));
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
    if let Some(Asked {
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
        &Message::response(status, &sending, request, false)?,
        true,
        &params_for(key, opts),
    )?;
    Ok(signed(key, &base, opts, &sending, headers))
}

/// Verify a signed request, in the KERI profile's section 9 order so a message has exactly one
/// correct refusal.
///
/// `max_age` is a required decision ([`MaxAge`]), and left [`MaxAge::Unstated`] it is
/// `InvalidArgument` (`this.i` @65u2932c). `max_age` and `skew`, when given, are positive; anything
/// else is `InvalidArgument` (@5zrf8gjk), as is a method that is not an HTTP token, an [`Authorities::Unstated`], or
/// an empty set of hosts. A target beginning with "/" is origin-form, whatever follows, and its
/// `@authority` is the Host header, checked as any authority is; anything else must be a scheme,
/// "://" and an authority. A target of any other shape, holding a "#", a space or a control
/// character, or whose authority's port is not a number from 0 to 65535, is a base that cannot be
/// built, so a covered derived component makes it a `SignatureMismatch`. The Signature, Signature-Input and Content-Digest headers are bounded
/// before they are parsed, at [`MAX_FIELD_BYTES`] each, [`MAX_DICTIONARY_MEMBERS`] members,
/// [`MAX_INNER_LIST_ITEMS`] items in an inner list and [`MAX_PARAMETERS`] parameters on an item,
/// and a header over any of them is malformed.
pub fn verify_request(
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    opts: &VerifyOptions,
) -> Result<Verdict> {
    check_window(opts)?;
    check_expected_keyid(&opts.expected_keyid, false)?;
    check_authorities(&opts.authorities)?;
    let minimum = stated(&opts.minimum, Some(&DEFAULT_MINIMUM), &REQUEST_MINIMUM)?;
    let headers = &canonical(headers)?;
    verify(
        &Message::request(method, url, headers, true)?,
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
/// announces. `expected_keyid` is a required decision ([`ExpectedKeyid`]): the AID the client is
/// talking to (profile R1), or [`ExpectedKeyid::Unchecked`]. So is `max_age` ([`MaxAge`]), as for
/// a request, and it is checked before the 401. Left at [`Minimum::Default`] the minimum is
/// [`RESPONSE_MINIMUM`], so the `request` it answers must be supplied for its `req` components to
/// be read, and a response verified without one is `MissingComponent` (`this.i` @524c8qgv);
/// [`Minimum::Off`] is the explicit opt-out. A response covering
/// `"content-digest";req` verified against a `request` whose body is `None` is `InvalidArgument`:
/// that digest is recomputed over the request body, and fiki cannot check a body it was not given.
/// So is `authorities`, which a response has no use for.
pub fn verify_response(
    status: u16,
    headers: &BTreeMap<String, String>,
    request: Option<&Request>,
    opts: &VerifyOptions,
) -> Result<Verdict> {
    check_window(opts)?;
    check_expected_keyid(&opts.expected_keyid, true)?;
    let minimum = stated(&opts.minimum, Some(&RESPONSE_MINIMUM), &RESPONSE_MINIMUM)?;
    if matches!(opts.authorities, Authorities::Served(_)) {
        return Err(Error::new(
            Kind::InvalidArgument,
            "A response has no @authority of its own, so served authorities do not apply to one; \
             pass authorities when verifying the request.",
        ));
    }
    let headers = &canonical(headers)?;
    let asked = canonical_request(request)?;
    let request = asked.as_ref();
    // An empty Signature is no signature: the same unsigned 401 (@5zrf8gjk).
    if status == 401 && headers.get("signature").map_or(true, String::is_empty) {
        return Err(Error::new(
            Kind::Unauthenticated,
            "The server answered 401 without signing the answer, so the request was not \
             authenticated and the body of the refusal cannot be trusted.",
        ));
    }
    verify(
        &Message::response(status, headers, request, true)?,
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
    response: Option<Option<&Asked>>,
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
        let request_had_body = request.is_some_and(|r| has_content(r.body));
        check_minimum(items, minimum, has_body, request_had_body)?;
    }
    // Served authorities bind the signature to a host only if it commits to one, so supplying
    // them makes @authority required (@605z9tnw): coverage, before the key, as section 9 orders.
    if matches!(opts.authorities, Authorities::Served(_)) {
        check_minimum(items, &[component("@authority")?], false, false)?;
    }

    let keyid = match inner.param("keyid") {
        Some(Value::Text(keyid)) => Some(keyid.clone()),
        _ => None,
    };
    // Section 9's key steps in order (@5zrf8gjk): what the keyid alone shows, then the expected
    // keyid, and only then the resolver, which is never asked about a keyid already refused.
    let local = local_key(opts, keyid.as_deref())?;
    if let ExpectedKeyid::Is(expected) = &opts.expected_keyid {
        if keyid.as_ref() != Some(expected) {
            let signer = keyid.clone().unwrap_or_default();
            return Err(Error::detailed(
                Kind::UnknownKey,
                format!(
                    "This message is signed by {}, and the one expected is {}.",
                    shown(&signer),
                    shown(expected)
                ),
                signer,
            ));
        }
    }
    let (public, aid) = match local {
        Local::Found(public, aid) => (public, aid),
        Local::Resolve(resolver, keyid) => resolved(resolver, keyid)?,
    };
    if let Some(Value::Text(alg)) = inner.param("alg") {
        if alg != ALG {
            return Err(Error::detailed(
                Kind::UnsupportedAlgorithm,
                format!(
                    "This signature is made with {}, and fiki verifies only {ALG}.",
                    shown(alg)
                ),
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

    if let Authorities::Served(served) = &opts.authorities {
        for item in items.iter().filter(|i| i.text() == Some("@authority")) {
            let value = crate::base::value_of(item, message)?;
            if !served.contains(&value) {
                return Err(Error::detailed(
                    Kind::SignatureMismatch,
                    format!(
                        "The signature covers the authority {}, which this verifier does not \
                         serve, so it was signed for somebody else.",
                        shown(&value)
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
            let Some(content) = request.body else {
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
    // Only SP and HTAB are optional whitespace (@5zrf8gjk); str::trim would also take a no-break
    // space or a vertical tab, and read "0\u{a0}" as a length of zero.
    match found
        .get("content-length")
        .map(|l| l.trim_matches([' ', '\t']))
    {
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
                brief(&spec_of(item))
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

    let signatures = parse_bounded(raw_signature, "Signature", Kind::MalformedSignature)?;
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
    let inputs = parse_bounded(raw_input, "Signature-Input", Kind::MalformedSignatureInput)?;
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
                "The Signature header carries no entry labelled {}, so the covered components \
                 describe a signature that is not here.",
                shown(label)
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

/// Parse one signature-related header, bounded before it is read (`this.i` @5zrf8gjk): its size on
/// the raw field value, before any trimming or parsing, then its counts on what parsed. Any refusal
/// is `kind`, the header's own malformed kind.
fn parse_bounded(raw: &str, name: &str, kind: Kind) -> Result<Vec<(String, Member)>> {
    if raw.len() > MAX_FIELD_BYTES {
        return Err(Error::new(
            kind,
            format!(
                "The {name} header is {} bytes, and fiki reads one of at most {MAX_FIELD_BYTES}.",
                raw.len()
            ),
        ));
    }
    let parsed = parse_dictionary(raw).map_err(|_| {
        Error::new(
            kind,
            format!(
                "I could not parse the {name} header; it is spelled as an RFC 8941 dictionary."
            ),
        )
    })?;
    let too_many = |what: &str, limit: usize| {
        Err(Error::new(
            kind,
            format!(
                "The {name} header has more than {limit} {what}, which is more than fiki reads \
                 from any honest signer."
            ),
        ))
    };
    // A field of nothing but optional whitespace is present and says nothing, which is no RFC 8941
    // dictionary a signer meant: malformed, as every port says alike (review B7).
    if parsed.is_empty() {
        return Err(Error::new(
            kind,
            format!("The {name} header holds no members, so there is nothing in it to read."),
        ));
    }
    if parsed.len() > MAX_DICTIONARY_MEMBERS {
        return too_many("members", MAX_DICTIONARY_MEMBERS);
    }
    for (_, member) in &parsed {
        let (items, params) = match member {
            Member::Item(item) => (&[][..], &item.params),
            Member::List(list) => (&list.items[..], &list.params),
        };
        if items.len() > MAX_INNER_LIST_ITEMS {
            return too_many("items in one inner list", MAX_INNER_LIST_ITEMS);
        }
        let most = items
            .iter()
            .map(|item| item.params.len())
            .max()
            .unwrap_or(0);
        if params.len().max(most) > MAX_PARAMETERS {
            return too_many("parameters on one item", MAX_PARAMETERS);
        }
    }
    Ok(parsed)
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
                brief(&crate::sfv::serialize_item(item))
            ));
        };
        if !name.starts_with('@') && name != name.to_ascii_lowercase() {
            return malformed(format!(
                "The covered field {} is not lowercase, and RFC 9421 section 2.1 requires field \
                 names in the covered list to be lowercased by the signer.",
                shown(name)
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
        // when expected_aid names the key (@5xde8s6l). MissingKey, as every port names it.
        return Err(Error::new(
            Kind::MissingKey,
            "This signature carries no keyid, which the verifier's policy requires even though \
             the key was named.",
        ));
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
                    "The signature parameter {} is not one fiki understands; it accepts created, \
                     expires, nonce, alg, keyid, tag.",
                    shown(name)
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
        // A time before 1970 is no time a signer could have meant (`this.i` @524c8qgv). Zero is a
        // time, so this is a sign test and never a truthiness one.
        if let Value::Integer(time @ ..=-1) = value {
            return malformed(format!(
                "The signature parameter \"{name}\" is {time}, and a UNIX time is not negative."
            ));
        }
    }
    Ok(list)
}

/// Every key check that needs nothing beyond the keyid itself (profile section 9).
///
/// The key to verify with and the identity to report when no resolver is needed, or `None` when
/// the resolver decides. Either way a keyid that is not well formed is refused here, before the
/// expected keyid is compared and before any resolver sees it (`this.i` @5zrf8gjk).
fn local_key<'a>(opts: &'a VerifyOptions, keyid: Option<&'a str>) -> Result<Local<'a>> {
    if let Some(aid) = &opts.expected_aid {
        let public = verifying_key(aid)?;
        return Ok(Local::Found(public, aid_of(public.as_bytes())));
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
                "The keyid {} is shaped like an AID and is not its canonical spelling, so it is not \
                 an AID at all.",
                shown(keyid)
            )));
        }
        return Ok(Local::Resolve(resolver, keyid));
    }
    let raw = raw_keyid(keyid).ok_or_else(|| {
        malformed(format!(
            "The keyid {} is not a base64url-encoded 32-byte Ed25519 public key: that is exactly \
             43 characters from the base64url alphabet, unpadded, in the key's own spelling.",
            shown(keyid)
        ))
    })?;
    let public = public_key(&raw).ok_or_else(|| {
        malformed(format!(
            "The keyid {} is not a usable Ed25519 public key: it is not a point on the curve, or it \
             is a small-order point, under which a signature proves nothing.",
            shown(keyid)
        ))
    })?;
    Ok(Local::Found(public, aid_of(&raw)))
}

/// What the keyid alone decided: the key and the identity to report, or a resolver to ask.
enum Local<'a> {
    Found(VerifyingKey, String),
    Resolve(&'a Resolver, &'a str),
}

/// The resolver's key for a keyid already found well formed, and the keyid it vouched for.
fn resolved(resolver: &Resolver, keyid: &str) -> Result<(VerifyingKey, String)> {
    // The resolver is authoritative: fiki never falls back to decoding the keyid, because a
    // transferable prefix that embeds a key embeds its INCEPTION key (@6g9zjsv9).
    let raw = resolver(keyid)?.ok_or_else(|| {
        Error::detailed(
            Kind::UnknownKey,
            format!(
                "No key is known for the keyid {}, so the signature cannot be checked.",
                shown(keyid)
            ),
            keyid,
        )
    })?;
    let public = public_key(&raw).ok_or_else(|| {
        Error::detailed(
            Kind::MalformedKey,
            format!(
                "The key resolved for {} is not a usable Ed25519 public key: it is not a point on \
                 the curve, or it is a small-order point, under which a signature proves nothing.",
                shown(keyid)
            ),
            keyid,
        )
    })?;
    Ok((public, keyid.to_string()))
}

/// `max_age` is a decision the caller made (`this.i` @65u2932c), and a freshness window, when
/// given, is a positive whole number of seconds (@5zrf8gjk).
///
/// The KERI profile's section 3 says so, and a zero or negative one would refuse every honest
/// message or none. [`MaxAge::Unchecked`] declines the age check; a `skew` of `None` takes
/// [`DEFAULT_SKEW`], since the expiry check uses a skew whatever `max_age` is.
fn check_window(opts: &VerifyOptions) -> Result<()> {
    if opts.max_age == MaxAge::Unstated {
        return Err(Error::new(
            Kind::InvalidArgument,
            "max_age is a required decision: state the age this verifier tolerates, such as \
             MaxAge::seconds(300), or MaxAge::Unchecked to decline the check. The signer's expires \
             is enforced either way.",
        ));
    }
    let max_age = opts.max_age.seconds_or_none();
    for (name, value) in [("max_age", max_age), ("skew", opts.skew)] {
        if let Some(value) = value.filter(|v| *v <= 0) {
            return Err(Error::detailed(
                Kind::InvalidArgument,
                format!(
                    "{name} is {value}, and a freshness window is a positive number of seconds."
                ),
                value.to_string(),
            ));
        }
    }
    Ok(())
}

/// Enforce the verifier's `max_age`, then the signer's `expires` (profile section 9).
fn check_freshness(list: &InnerList, opts: &VerifyOptions) -> Result<()> {
    let expires = match list.param("expires") {
        Some(Value::Integer(n)) => Some(*n),
        _ => None,
    };
    let max_age = opts.max_age.seconds_or_none();
    if expires.is_none() && max_age.is_none() {
        return Ok(());
    }
    let skew = opts.skew.unwrap_or(DEFAULT_SKEW);
    let stamp = now_or(opts.now);
    // Compared in i128, where no i64 sum or difference can wrap (@5zrf8gjk): a caller's enormous
    // window or a clock at either end of i64 is compared, never overflowed.
    let wide = |n: i64| i128::from(n);

    if let Some(max_age) = max_age {
        let too_old = |why: String| Err(Error::new(Kind::SignatureTooOld, why));
        let Some(Value::Integer(created)) = list.param("created") else {
            return too_old(format!(
                "This signature carries no created timestamp, so its age cannot be checked against \
                 the {max_age}-second limit you asked for."
            ));
        };
        if wide(stamp) - wide(*created) > wide(max_age) + wide(skew) {
            return too_old(format!(
                "This signature was created at {created}, which is more than {max_age} seconds \
                 before {stamp}, so it is too old to accept."
            ));
        }
        if wide(*created) - wide(stamp) > wide(skew) {
            return too_old(format!(
                "This signature claims to have been created at {created}, which is in the future \
                 relative to {stamp} by more than the {skew}-second skew allowance."
            ));
        }
    }
    match expires {
        Some(expires) if wide(stamp) > wide(expires) + wide(skew) => Err(Error::new(
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
    let header = header.ok_or_else(|| {
        malformed(
            "The signature covers content-digest and the message carries no Content-Digest \
             header, so there is no digest to read.",
        )
    })?;
    let parsed = parse_bounded(header, "Content-Digest", Kind::MalformedDigest)?;
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

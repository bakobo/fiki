//! The RFC 9421 signature base, section 2.5 (`this.i` @2hwvpm42, @7f28p7xk).
//!
//! Public, not internal. When two implementations disagree about a signature, the base is where
//! they disagree, and a caller debugging an interop failure needs to see the bytes both sides
//! actually hashed.
//!
//! Derived components fiki builds: `@method`, `@authority`, `@path`, `@query` in a request, and
//! `@status` in a response, which may also name its request's components with the `req` parameter
//! of section 2.4. Anything else is refused rather than skipped — a component silently dropped from
//! the base is one the caller believes is covered and is not.

use std::collections::{BTreeMap, HashSet};

use crate::errors::{Error, Kind, Result};
use crate::sfv::{
    parse_item, serialize_inner_list, serialize_item, serialize_parameters, InnerList, Item, Value,
};

/// Derived components fiki builds in a request, and through `req` from a response.
pub const DERIVED: [&str; 4] = ["@method", "@authority", "@path", "@query"];

/// The one derived component a response has of its own (RFC 9421 section 2.2.9). Every request
/// component reaches a response only through `req`.
pub const RESPONSE_DERIVED: [&str; 1] = ["@status"];

/// `@method`, `@authority`, `@path`, `@query` — plus `content-digest` whenever there is a body.
/// This closes the query, host, and body gaps that heti's KERI dialect leaves open and structurally
/// cannot close. `created` is a signature parameter rather than a component.
pub const DEFAULT_COVERED: [&str; 4] = ["@method", "@authority", "@path", "@query"];

/// The covered component that binds a body.
pub const CONTENT_DIGEST: &str = "content-digest";

/// The only component parameter fiki supports, and only in a response (RFC 9421 section 2.4).
const REQ: &str = "req";

/// RFC 8941 section 3.3.1: an integer has at most fifteen digits, and fiki signs no negative time.
const SF_INTEGER_MAX: i64 = 999_999_999_999_999;

/// RFC 3986 section 3.2.3 reads a port as digits; RFC 9110's ports are 16-bit.
const PORT_MAX: u32 = 65535;

/// RFC 9110 section 5.6.2: one or more tchar. A method is a token (section 9.1), and so is a field
/// name (section 5.1), which fiki further requires lowercased in a covered list.
pub(crate) fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// RFC 8941 section 3.1.2: a dictionary key, which is what a signature label is.
fn is_key(text: &str) -> bool {
    let mut bytes = text.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'*'))
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.*-".contains(&b))
}

/// A request's method is an RFC 9110 token, covered or not, or the call is a mistake. Its case is
/// kept as given (`this.i` @22g0xkr8). Checked wherever a request message is built, on sign and
/// verify alike (@5zrf8gjk): an empty or spaced method is never a request anybody sent.
fn check_method(method: &str) -> Result<()> {
    if is_token(method) {
        return Ok(());
    }
    Err(Error::detailed(
        Kind::InvalidArgument,
        format!(
            "The method {method:?} is not an HTTP method: a method is one or more token \
             characters, with no spaces, line breaks or separators."
        ),
        method,
    ))
}

/// A signature label is an RFC 8941 dictionary key, or the call is a mistake (@5zrf8gjk): it is
/// written into both headers as given, so a line break there would forge a header line.
pub(crate) fn check_label(label: &str) -> Result<()> {
    if is_key(label) {
        return Ok(());
    }
    Err(Error::detailed(
        Kind::InvalidArgument,
        format!(
            "The label {label:?} is not an RFC 8941 key: it starts with a lowercase letter or '*' \
             and continues with lowercase letters, digits, '_', '-', '.' and '*'."
        ),
        label,
    ))
}

/// What a signer serializes must be serializable, or the call is a mistake (@5zrf8gjk).
///
/// `created` and `expires` are RFC 8941 integers that are not negative; `keyid`, `alg`, `nonce`
/// and `tag` are sf-strings, printable ASCII only. Checked before anything is serialized, so a line
/// break is refused by name rather than written into Signature-Input.
fn check_signer_params(params: &SignatureParams) -> Result<()> {
    for (name, value) in [("created", params.created), ("expires", params.expires)] {
        if let Some(value) = value.filter(|v| !(0..=SF_INTEGER_MAX).contains(v)) {
            return Err(Error::detailed(
                Kind::InvalidArgument,
                format!(
                    "{name} is {value}, and RFC 8941 carries an integer of at most fifteen \
                     digits; fiki signs one from 0 to {SF_INTEGER_MAX}."
                ),
                value.to_string(),
            ));
        }
    }
    for (name, value) in [
        ("keyid", &params.keyid),
        ("alg", &params.alg),
        ("nonce", &params.nonce),
        ("tag", &params.tag),
    ] {
        if let Some(value) = value
            .as_deref()
            .filter(|v| !v.bytes().all(|b| (0x20..=0x7e).contains(&b)))
        {
            return Err(Error::detailed(
                Kind::InvalidArgument,
                format!(
                    "The {name} {value:?} holds a character outside printable ASCII, which an RFC \
                     8941 string cannot carry; a line break there would forge a header line."
                ),
                value,
            ));
        }
    }
    Ok(())
}

/// The RFC 9421 signature parameters a signer sets.
#[derive(Debug, Default, Clone)]
pub struct SignatureParams {
    pub created: Option<i64>,
    pub keyid: Option<String>,
    pub alg: Option<String>,
    pub expires: Option<i64>,
    pub nonce: Option<String>,
    pub tag: Option<String>,
}

/// The request a response answers, which a response's `req` components are read from.
#[derive(Debug, Default, Clone)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    /// The request's content. A response binding `"content-digest";req` is checked against it, and
    /// a request with no content binds no digest (`this.i` @7p9s3g9k).
    pub body: Option<Vec<u8>>,
}

/// The spelling of a request component named from a response: `req("@path")` is `"@path";req`.
pub fn req(name: &str) -> String {
    serialize_item(&Item {
        value: Value::Text(name.to_ascii_lowercase()),
        params: vec![(REQ.into(), Value::Boolean(true))],
    })
}

/// A component identifier from a caller's spelling of it: a plain name (`"@method"`,
/// `"Content-Digest"`) or its RFC 8941 serialization with parameters (`"\"@method\";req"`). Names
/// are lowercased as a convenience to a local caller; a name parsed from the wire is never
/// lowercased, and is refused instead when it is not already. A field name that is not a token is
/// the caller's mistake, `InvalidArgument`, because it would be serialized into Signature-Input as
/// given (@5zrf8gjk); a derived name fiki does not build is refused later, as
/// `UnsupportedComponent`, which names it.
pub(crate) fn component(spec: &str) -> Result<Item> {
    let item = component_item(spec)?;
    match item.text() {
        Some(name) if !name.starts_with('@') && !is_token(name) => Err(Error::detailed(
            Kind::InvalidArgument,
            format!(
                "{spec:?} is not a component fiki can name: a field is named by an HTTP field \
                 name, one or more token characters, and a derived component by its @ name."
            ),
            spec,
        )),
        _ => Ok(item),
    }
}

fn component_item(spec: &str) -> Result<Item> {
    if !spec.starts_with('"') {
        return Ok(Item {
            value: Value::Text(spec.to_ascii_lowercase()),
            params: Vec::new(),
        });
    }
    let mut item = parse_item(spec).map_err(|_| {
        Error::detailed(
            Kind::UnsupportedComponent,
            format!(
                "fiki cannot read {spec} as a component identifier; name a component plainly, \
                 as \"@path\", or in its serialized form, as '\"@path\";req'."
            ),
            spec,
        )
    })?;
    if let Value::Text(name) = &mut item.value {
        *name = name.to_ascii_lowercase();
    }
    Ok(item)
}

/// The inverse of [`component`]: a plain name when it has no parameters.
pub(crate) fn spec_of(item: &Item) -> String {
    match (item.text(), item.params.is_empty()) {
        (Some(name), true) => name.to_string(),
        _ => serialize_item(item),
    }
}

/// What two identifiers must share to be the same component. Parameter order is not it.
pub(crate) fn identity(item: &Item) -> (String, String) {
    let mut params = item.params.clone();
    params.sort_by(|a, b| a.0.cmp(&b.0));
    (
        item.text().unwrap_or_default().to_string(),
        serialize_parameters(&params),
    )
}

fn is_req(item: &Item) -> bool {
    item.params
        .iter()
        .any(|(k, v)| k == REQ && *v == Value::Boolean(true))
}

/// Refuse a covered list fiki cannot build faithfully: duplicates first, then the unsupported.
///
/// That order is the KERI profile's section 9, so a list that is both has one correct refusal.
pub(crate) fn check_covered(items: &[Item], response: bool) -> Result<()> {
    // A set, because the list is untrusted and a linear search per item is quadratic in it
    // (bakobo/fiki#8).
    let mut seen = HashSet::new();
    for item in items {
        if !seen.insert(identity(item)) {
            return Err(Error::detailed(
                Kind::DuplicateComponent,
                format!(
                    "The covered components name {} twice, so the signature base would not be \
                     what either copy says it is.",
                    spec_of(item)
                ),
                spec_of(item),
            ));
        }
    }

    for item in items {
        let req = is_req(item);
        let foreign = item.params.iter().any(|(k, _)| k != REQ);
        if foreign || (item.params.iter().any(|(k, _)| k == REQ) && !(req && response)) {
            return Err(Error::detailed(
                Kind::UnsupportedComponent,
                format!(
                    "fiki does not support the component {}: the only component parameter it \
                     supports is \"{REQ}\", and only in a response.",
                    spec_of(item)
                ),
                spec_of(item),
            ));
        }
        let name = item.text().unwrap_or_default();
        if name.starts_with('@') {
            let supported: &[&str] = if req || !response {
                &DERIVED
            } else {
                &RESPONSE_DERIVED
            };
            if !supported.contains(&name) {
                return Err(Error::detailed(
                    Kind::UnsupportedComponent,
                    format!(
                        "fiki does not build the derived component {} in a {}; it builds {}.",
                        spec_of(item),
                        if response { "response" } else { "request" },
                        supported.join(", ")
                    ),
                    spec_of(item),
                ));
            }
        }
    }
    Ok(())
}

const DEFAULT_PORTS: [(&str, u32); 4] = [("http", 80), ("https", 443), ("ws", 80), ("wss", 443)];

/// A request target, split without a URL crate: fiki needs the scheme, authority, path and raw
/// query and nothing else, and pulling in a parser to get four slices would be a dependency for
/// string handling.
pub(crate) struct Target {
    pub scheme: Option<String>,
    pub authority: Option<String>,
    pub path: String,
    pub query: String,
}

/// The URL as every port reads it, which is how Python's `urlsplit` reads it (`this.i` @2n99rej7,
/// ruled by the conductor for the 0.8.0 sweep): leading C0 controls and spaces stripped, trailing
/// ones kept, and TAB, CR and LF removed wherever they are, as the WHATWG URL parser does.
fn cleaned(raw: &str) -> String {
    raw.trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect()
}

pub(crate) fn split_target(raw: &str) -> Target {
    let raw = cleaned(raw);
    let raw = raw.as_str();
    let (scheme, rest) = match raw.find("://") {
        Some(at)
            if raw[..at]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) =>
        {
            (Some(raw[..at].to_ascii_lowercase()), &raw[at + 3..])
        }
        _ => (None, raw),
    };
    let (authority, rest) = match scheme {
        Some(_) => {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            (Some(rest[..end].to_string()), &rest[end..])
        }
        None => (None, rest),
    };
    let rest = rest.split('#').next().unwrap_or("");
    let (path, query) = match rest.find('?') {
        Some(at) => (&rest[..at], &rest[at + 1..]),
        None => (rest, ""),
    };
    Target {
        scheme,
        authority,
        path: if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        },
        query: query.to_string(),
    }
}

/// A message whose components fiki can read: a request, or a response and the request it answers.
///
/// `received` is a message handed to a verifier rather than built by a signer, which decides what a
/// URL fiki cannot read is: a base that cannot be built when it arrived, a caller error when
/// signing (@5zrf8gjk).
pub(crate) struct Message {
    headers: BTreeMap<String, String>,
    method: Option<String>,
    url: String,
    target: Option<Target>,
    status: Option<u16>,
    request: Option<Box<Message>>,
    received: bool,
}

impl Message {
    /// `headers` are already canonical (`canonical`), so only their values are trimmed here.
    pub fn request(
        method: &str,
        url: &str,
        headers: &BTreeMap<String, String>,
        received: bool,
    ) -> Result<Self> {
        check_method(method)?;
        Ok(Message {
            headers: trimmed(headers),
            method: Some(method.to_string()),
            url: url.to_string(),
            target: Some(split_target(url)),
            status: None,
            request: None,
            received,
        })
    }

    pub fn response(
        status: u16,
        headers: &BTreeMap<String, String>,
        request: Option<&Asked>,
        received: bool,
    ) -> Result<Self> {
        Ok(Message {
            headers: trimmed(headers),
            method: None,
            url: String::new(),
            target: None,
            status: Some(status),
            request: request
                .map(|r| Message::request(r.method, r.url, &r.headers, received).map(Box::new))
                .transpose()?,
            received,
        })
    }

    /// A URL fiki cannot read: the caller's mistake when signing, an unbuildable base when not.
    ///
    /// The profile's section 9 names a base that cannot be built a signature mismatch, so a
    /// received URL whose port is not one is refused like any other base that does not verify,
    /// never as a failure outside fiki's taxonomy (@5zrf8gjk).
    fn unreadable(&self, reason: &str) -> Error {
        if self.received {
            return Error::detailed(
                Kind::SignatureMismatch,
                format!(
                    "The URL {:?} cannot be read: {reason} So there is no signature base to check \
                     the signature against.",
                    self.url
                ),
                &self.url,
            );
        }
        Error::detailed(
            Kind::InvalidArgument,
            format!("The URL {:?} cannot be read: {reason}", self.url),
            &self.url,
        )
    }
}

/// RFC 3986 section 3.2.3: any run of ASCII digits, read as a number (@5zrf8gjk), so `:000080` is
/// port 80 and the default port of http. An empty port is no port at all, as section 6.2.3
/// normalizes it. Leading zeros are dropped before the number is read, so no run of them overflows.
fn port(text: &str, message: &Message) -> Result<Option<u32>> {
    if text.is_empty() {
        return Ok(None);
    }
    let significant = text.trim_start_matches('0');
    if text.bytes().all(|b| b.is_ascii_digit()) && significant.len() <= 5 {
        // All zeros leaves nothing to parse, and is port 0.
        let number = significant.parse::<u32>().unwrap_or(0);
        if number <= PORT_MAX {
            return Ok(Some(number));
        }
    }
    Err(message.unreadable(&format!(
        "its port {text:?} is not a number from 0 to {PORT_MAX}."
    )))
}

fn authority(target: &Target, message: &Message) -> Result<String> {
    // RFC 9421 section 2.2.3: lowercase host, default port omitted. A relative URL falls back to
    // the Host header, which in HTTP/1.1 *is* the authority — the shape a server-side verifier
    // actually holds. Nothing is normalized away there, because without a scheme no port is a
    // default port.
    let headers = &message.headers;
    if let Some(raw) = &target.authority {
        // Read as written, after any userinfo. An IP-literal keeps its brackets, as RFC 3986
        // section 3.2.2 makes them part of the host, and nothing but a port may follow its ']'.
        let hostport = raw
            .rsplit_once('@')
            .map_or(raw.as_str(), |(_, after)| after);
        let (host, port_text) = match hostport.strip_prefix('[') {
            Some(literal) => {
                let Some((inside, rest)) = literal.split_once(']') else {
                    return Err(message.unreadable("its IP-literal has no closing ']'."));
                };
                let Some(port_text) = rest.strip_prefix(':').or((rest.is_empty()).then_some(""))
                else {
                    return Err(message.unreadable(
                        "something other than a port follows the ']' of its IP-literal.",
                    ));
                };
                (format!("[{inside}]"), port_text)
            }
            None if hostport.contains(['[', ']']) => {
                return Err(message.unreadable("it has a ']' with no IP-literal to close."));
            }
            None => {
                let (host, port_text) = hostport.split_once(':').unwrap_or((hostport, ""));
                (host.to_string(), port_text)
            }
        };
        let host = host.to_ascii_lowercase();
        let port = port(port_text, message)?;
        let default = target
            .scheme
            .as_deref()
            .and_then(|s| DEFAULT_PORTS.iter().find(|(name, _)| *name == s))
            .map(|(_, port)| *port);
        return Ok(match port {
            Some(port) if Some(port) != default => format!("{host}:{port}"),
            _ => host,
        });
    }
    headers
        .get("host")
        .map(|h| h.to_ascii_lowercase())
        .ok_or_else(|| {
            Error::detailed(
                Kind::MissingComponent,
                "The signature covers \"@authority\", but the URL carries no authority and the \
                 request has no Host header, so there is nothing to derive it from.",
                "@authority",
            )
        })
}

fn missing(item: &Item, why: &str) -> Error {
    Error::detailed(
        Kind::MissingComponent,
        format!("The signature covers {}, {why}", spec_of(item)),
        spec_of(item),
    )
}

fn component_value(item: &Item, message: &Message) -> Result<String> {
    let mut message = message;
    if is_req(item) {
        message = message.request.as_deref().ok_or_else(|| {
            missing(
                item,
                "which is read from the request this response answers, and no request was \
                 supplied.",
            )
        })?;
    }
    let name = item.text().unwrap_or_default();
    let target = message.target.as_ref();
    match (name, target) {
        // Section 2.2.9: the three-digit status code. Anything else is not a status this
        // component can carry, so there is no value to sign or to check.
        ("@status", _) => match message.status {
            Some(status @ 100..=999) => Ok(status.to_string()),
            other => Err(Error::detailed(
                Kind::MissingComponent,
                format!(
                    "The signature covers @status, and {} is not a three-digit HTTP status \
                     code, so there is no status line to build.",
                    other.map_or("a request".to_string(), |s| s.to_string())
                ),
                "@status",
            )),
        },
        // Section 2.2.1: the method as sent, with no case transformation (`this.i` @22g0xkr8).
        // Message::request checked it is a token (@5zrf8gjk).
        ("@method", _) => message
            .method
            .clone()
            .ok_or_else(|| missing(item, "and a response has no method.")),
        ("@authority", Some(target)) => authority(target, message),
        ("@path", Some(target)) => Ok(target.path.clone()),
        // Section 2.2.7: the whole query string including the leading "?", percent-encoding
        // preserved, and a bare "?" when the request carries no query at all.
        ("@query", Some(target)) => Ok(format!("?{}", target.query)),
        _ => message.headers.get(name).cloned().ok_or_else(|| {
            missing(
                item,
                "but the message carries no value for it, so the signature base cannot be built.",
            )
        }),
    }
}

/// A component's value, refused when it has no single serialization both sides agree on.
///
/// A line break inside a value would forge a line of the base, and a byte outside visible ASCII is
/// encoded differently by different stacks. The KERI profile names such a base unbuildable, and so
/// a signature mismatch (`this.i` @2f227n4r).
pub(crate) fn value_of(item: &Item, message: &Message) -> Result<String> {
    let value = component_value(item, message)?;
    if value
        .chars()
        .any(|c| !(c == '\t' || (' '..='~').contains(&c)))
    {
        return Err(Error::detailed(
            Kind::SignatureMismatch,
            format!(
                "The value of {} contains a line break, a control character or a non-ASCII \
                 character, so there is no signature base both sides would build from it.",
                spec_of(item)
            ),
            spec_of(item),
        ));
    }
    Ok(value)
}

/// A caller's header map with every field name lowercased, or `InvalidArgument` when two names
/// are equal case-insensitively (`this.i` @4kcthnkn). A `BTreeMap`'s keys are case-sensitive and
/// HTTP's field names are not, so such a map holds two values for one field, and lowering it would
/// silently keep one: a response signed over `x-role: member` would verify while also carrying
/// `X-Role: admin`. Every public entry point canonicalizes once, and every later step reads that.
pub(crate) fn canonical(headers: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        // By presence, not by what an insert hands back (@5zrf8gjk, D-Q9ZT).
        if out.contains_key(&lower) {
            return Err(Error::detailed(
                Kind::InvalidArgument,
                format!(
                    "The headers name the field \"{lower}\" more than once in different case, so \
                     it has two values and fiki cannot know which one was meant; combine them into \
                     one entry before signing or verifying."
                ),
                lower,
            ));
        }
        out.insert(lower, value.clone());
    }
    Ok(out)
}

/// The request a response answers, with its headers canonical and everything else borrowed:
/// the body may be large, and it is only ever hashed (bakobo/fiki#8).
pub(crate) struct Asked<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: BTreeMap<String, String>,
    pub body: Option<&'a [u8]>,
}

/// A view of `request` whose headers are canonical, for a response's `req` components.
pub(crate) fn canonical_request(request: Option<&Request>) -> Result<Option<Asked<'_>>> {
    request
        .map(|r| {
            Ok(Asked {
                method: &r.method,
                url: &r.url,
                headers: canonical(&r.headers)?,
                body: r.body.as_deref(),
            })
        })
        .transpose()
}

fn trimmed(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    // The names are canonical already, lowercased once by `canonical` (@5zrf8gjk). Values lose
    // leading and trailing SP and HTAB, the only optional whitespace RFC 9110 section 5.5 allows
    // around a field value, and nothing else: str::trim would also strip a CR or LF, and value_of
    // must see those to refuse them (`this.i` @56qu7gyw).
    headers
        .iter()
        .map(|(name, value)| (name.clone(), value.trim_matches([' ', '\t']).to_string()))
        .collect()
}

/// Every line of the signature base except the trailing `@signature-params`.
pub(crate) fn lines_for(items: &[Item], message: &Message) -> Result<Vec<String>> {
    items
        .iter()
        .map(|item| {
            Ok(format!(
                "{}: {}",
                serialize_item(item),
                value_of(item, message)?
            ))
        })
        .collect()
}

/// The `@signature-params` line closes the base. Order is the signer's choice — a verifier
/// reserializes whatever it received — so fiki fixes one order and keeps it, which makes its own
/// output reproducible.
pub(crate) fn finish(mut lines: Vec<String>, items: &[Item], params: &SignatureParams) -> Vec<u8> {
    let mut list = InnerList {
        items: items.to_vec(),
        params: Vec::new(),
    };
    let text = |s: &Option<String>| s.clone().map(Value::Text);
    for (name, value) in [
        ("created", params.created.map(Value::Integer)),
        ("expires", params.expires.map(Value::Integer)),
        ("nonce", text(&params.nonce)),
        ("alg", text(&params.alg)),
        ("keyid", text(&params.keyid)),
        ("tag", text(&params.tag)),
    ] {
        if let Some(value) = value {
            list.params.push((name.into(), value));
        }
    }
    lines.push(format!(
        "\"@signature-params\": {}",
        serialize_inner_list(&list)
    ));
    lines.join("\n").into_bytes()
}

pub(crate) fn components(covered: &[String]) -> Result<Vec<Item>> {
    covered.iter().map(|spec| component(spec)).collect()
}

pub(crate) fn base_for(
    items: &[Item],
    message: &Message,
    response: bool,
    params: &SignatureParams,
) -> Result<Vec<u8>> {
    check_signer_params(params)?;
    check_covered(items, response)?;
    Ok(finish(lines_for(items, message)?, items, params))
}

/// Build the RFC 9421 signature base for a request.
///
/// `covered` names each component plainly or in serialized form. Refuses a component named twice
/// as `DuplicateComponent`, a derived component outside [`DERIVED`] or any component parameter as
/// `UnsupportedComponent`, a covered header the request does not carry as `MissingComponent`, and
/// a value with no single serialization as `SignatureMismatch`. Mistakes in the call are
/// `InvalidArgument` (`this.i` @5zrf8gjk): a method that is not an HTTP token, a URL whose port is
/// not a number from 0 to 65535 or whose IP-literal is followed by anything but a port, a field
/// name that is not a token, a `created` or `expires` outside 0 to 999999999999999, and a `keyid`,
/// `alg`, `nonce` or `tag` outside printable ASCII.
pub fn signature_base(
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    covered: &[String],
    params: &SignatureParams,
) -> Result<Vec<u8>> {
    let headers = canonical(headers)?;
    let message = Message::request(method, url, &headers, false)?;
    base_for(&components(covered)?, &message, false, params)
}

/// Build the RFC 9421 signature base for a response (sections 2.2.9 and 2.4).
///
/// `request` is the request being answered, which `req` components are read from — spelled
/// [`req`]`("@path")` or `"\"@path\";req"`. Without one, a `req` component is a
/// `MissingComponent`.
pub fn response_signature_base(
    status: u16,
    headers: &BTreeMap<String, String>,
    request: Option<&Request>,
    covered: &[String],
    params: &SignatureParams,
) -> Result<Vec<u8>> {
    let headers = canonical(headers)?;
    let request = canonical_request(request)?;
    let message = Message::response(status, &headers, request.as_ref(), false)?;
    base_for(&components(covered)?, &message, true, params)
}

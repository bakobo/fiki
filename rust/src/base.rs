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

use std::collections::BTreeMap;

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
/// lowercased, and is refused instead when it is not already.
pub(crate) fn component(spec: &str) -> Result<Item> {
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
    let mut seen = Vec::new();
    for item in items {
        let id = identity(item);
        if seen.contains(&id) {
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
        seen.push(id);
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

const DEFAULT_PORTS: [(&str, &str); 4] = [
    ("http", "80"),
    ("https", "443"),
    ("ws", "80"),
    ("wss", "443"),
];

/// A request target, split without a URL crate: fiki needs the scheme, authority, path and raw
/// query and nothing else, and pulling in a parser to get four slices would be a dependency for
/// string handling.
pub(crate) struct Target {
    pub scheme: Option<String>,
    pub authority: Option<String>,
    pub path: String,
    pub query: String,
}

pub(crate) fn split_target(raw: &str) -> Target {
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
pub(crate) struct Message {
    headers: BTreeMap<String, String>,
    method: Option<String>,
    target: Option<Target>,
    status: Option<u16>,
    request: Option<Box<Message>>,
}

impl Message {
    pub fn request(method: &str, url: &str, headers: &BTreeMap<String, String>) -> Self {
        Message {
            headers: lower_headers(headers),
            method: Some(method.to_string()),
            target: Some(split_target(url)),
            status: None,
            request: None,
        }
    }

    pub fn response(
        status: u16,
        headers: &BTreeMap<String, String>,
        request: Option<&Request>,
    ) -> Self {
        Message {
            headers: lower_headers(headers),
            method: None,
            target: None,
            status: Some(status),
            request: request.map(|r| Box::new(Message::request(&r.method, &r.url, &r.headers))),
        }
    }
}

fn authority(target: &Target, headers: &BTreeMap<String, String>) -> Result<String> {
    // RFC 9421 section 2.2.3: lowercase host, default port omitted. A relative URL falls back to
    // the Host header, which in HTTP/1.1 *is* the authority — the shape a server-side verifier
    // actually holds. Nothing is normalized away there, because without a scheme no port is a
    // default port.
    if let Some(raw) = &target.authority {
        let raw = raw.to_ascii_lowercase();
        let (host, port) = match raw.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => (host, Some(port)),
            _ => (raw.as_str(), None),
        };
        let default = target
            .scheme
            .as_deref()
            .and_then(|s| DEFAULT_PORTS.iter().find(|(name, _)| *name == s))
            .map(|(_, port)| *port);
        return Ok(match port {
            Some(port) if Some(port) != default => format!("{host}:{port}"),
            _ => host.to_string(),
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
        ("@method", _) => match message.method.as_deref() {
            None => Err(missing(item, "and a response has no method.")),
            // A request has a method; an empty one is a caller who lost it (@56qu7gyw).
            Some("") => Err(Error::new(
                Kind::InvalidArgument,
                "The method is empty, so there is no @method to sign or verify; pass the method \
                 exactly as it goes on the wire.",
            )),
            Some(method) => Ok(method.to_string()),
        },
        ("@authority", Some(target)) => authority(target, &message.headers),
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

pub(crate) fn lower_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    // Header field names are case-insensitive and appear lowercased in the base (section 2.1).
    // Values lose leading and trailing SP and HTAB, the only optional whitespace RFC 9110 section
    // 5.5 allows around a field value, and nothing else: str::trim would also strip a CR or LF,
    // and value_of must see those to refuse them (`this.i` @56qu7gyw).
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.to_ascii_lowercase(),
                value.trim_matches([' ', '\t']).to_string(),
            )
        })
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
    check_covered(items, response)?;
    Ok(finish(lines_for(items, message)?, items, params))
}

/// Build the RFC 9421 signature base for a request.
///
/// `covered` names each component plainly or in serialized form. Refuses a component named twice
/// as `DuplicateComponent`, a derived component outside [`DERIVED`] or any component parameter as
/// `UnsupportedComponent`, a covered header the request does not carry as `MissingComponent`, and
/// a value with no single serialization as `SignatureMismatch`.
pub fn signature_base(
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    covered: &[String],
    params: &SignatureParams,
) -> Result<Vec<u8>> {
    base_for(
        &components(covered)?,
        &Message::request(method, url, headers),
        false,
        params,
    )
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
    base_for(
        &components(covered)?,
        &Message::response(status, headers, request),
        true,
        params,
    )
}

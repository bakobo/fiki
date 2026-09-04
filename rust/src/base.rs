//! The RFC 9421 signature base, section 2.5 (`this.i` @2hwvpm42).
//!
//! Public, not internal. When two implementations disagree about a signature, the base is where
//! they disagree, and a caller debugging an interop failure needs to see the bytes both sides
//! actually hashed.

use std::collections::BTreeMap;

use crate::errors::{Error, Kind, Result};
use crate::sfv::{serialize_inner_list, InnerList, Value};

/// Derived components fiki builds. Anything else is refused rather than skipped — a component
/// silently dropped from the base is one the caller believes is covered and is not.
pub const DERIVED: [&str; 4] = ["@method", "@authority", "@path", "@query"];

/// `@method`, `@authority`, `@path`, `@query` — plus `content-digest` whenever there is a body.
/// This closes the query, host, and body gaps that heti's KERI dialect leaves open and
/// structurally cannot close. `created` is a signature parameter rather than a component.
pub const DEFAULT_COVERED: [&str; 4] = ["@method", "@authority", "@path", "@query"];

/// The covered component that binds a request body.
pub const CONTENT_DIGEST: &str = "content-digest";

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

fn component_value(
    component: &str,
    method: &str,
    target: &Target,
    headers: &BTreeMap<String, String>,
) -> Result<String> {
    match component {
        "@method" => Ok(method.to_ascii_uppercase()),
        "@authority" => authority(target, headers),
        "@path" => Ok(target.path.clone()),
        // Section 2.2.7: the whole query string including the leading "?", percent-encoding
        // preserved, and a bare "?" when the request carries no query at all.
        "@query" => Ok(format!("?{}", target.query)),
        _ if component.starts_with('@') => Err(Error::detailed(
            Kind::UnsupportedComponent,
            format!(
                "fiki does not build the derived component {component}; it builds {}.",
                DERIVED.join(", ")
            ),
            component,
        )),
        _ => headers.get(component).cloned().ok_or_else(|| {
            Error::detailed(
                Kind::MissingComponent,
                format!(
                    "The signature covers {component}, but the request carries no value for it."
                ),
                component,
            )
        }),
    }
}

pub(crate) fn lower_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    // Header field names are case-insensitive and appear lowercased in the base (section 2.1);
    // values are stripped of leading and trailing whitespace.
    headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect()
}

/// Every line of the signature base except the trailing `@signature-params`.
///
/// Split out because the verify side cannot call [`signature_base`]: it must reserialize the
/// parameters exactly as they arrived, in the order they arrived.
pub(crate) fn component_lines(
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    covered: &[String],
) -> Result<Vec<String>> {
    let target = split_target(url);
    let lowered = lower_headers(headers);
    covered
        .iter()
        .map(|component| {
            let component = component.to_ascii_lowercase();
            let value = component_value(&component, method, &target, &lowered)?;
            Ok(format!("\"{component}\": {value}"))
        })
        .collect()
}

/// Build the RFC 9421 signature base for a request.
pub fn signature_base(
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    covered: &[String],
    params: &SignatureParams,
) -> Result<Vec<u8>> {
    let components: Vec<String> = covered.iter().map(|c| c.to_ascii_lowercase()).collect();
    let mut lines = component_lines(method, url, headers, &components)?;

    // Order is the signer's choice — a verifier reserializes whatever it received — so fiki fixes
    // one order and keeps it, which makes its own output reproducible.
    let mut list = InnerList {
        items: components,
        params: Vec::new(),
    };
    if let Some(created) = params.created {
        list.params
            .push(("created".into(), Value::Integer(created)));
    }
    if let Some(expires) = params.expires {
        list.params
            .push(("expires".into(), Value::Integer(expires)));
    }
    if let Some(nonce) = &params.nonce {
        list.params
            .push(("nonce".into(), Value::Text(nonce.clone())));
    }
    if let Some(alg) = &params.alg {
        list.params.push(("alg".into(), Value::Text(alg.clone())));
    }
    if let Some(keyid) = &params.keyid {
        list.params
            .push(("keyid".into(), Value::Text(keyid.clone())));
    }
    if let Some(tag) = &params.tag {
        list.params.push(("tag".into(), Value::Text(tag.clone())));
    }
    lines.push(format!(
        "\"@signature-params\": {}",
        serialize_inner_list(&list)
    ));
    Ok(lines.join("\n").into_bytes())
}

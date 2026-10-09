//! The 0.8.0 cross-port sweep: every port gives the same answer to the same input (`this.i`
//! @5zrf8gjk).
//!
//! One group per rule of the sweep, numbered as the spec numbers them, mirroring fiki-py's
//! `py/tests/test_sweep.py`. Caller errors are tested here and not in the vectors, because they are
//! API behaviour; everything a vector can pin is also in `vectors/` and `vectors/keri/`. Where
//! fiki-py tests a TypeError (a header, method or timestamp that is not the right type), Rust's
//! types make the input unrepresentable, so there is no test to write.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fiki::{
    content_digest, req, response_signature_base, sign_request, sign_response, signature_base,
    verify_request, verify_response, Authorities, ExpectedKeyid, Key, Kind, MaxAge, Minimum,
    Request, Resolver, SignOptions, SignatureParams, Verdict, VerifyOptions, REQUEST_MINIMUM,
};

/// The policy fiki 0.8 applied when a caller stated none: no minimum, no authority check, no
/// expected keyid and no age check. Format 3 makes a minimum the default for requests and responses
/// alike, and authorities and a response's expected keyid required decisions (`this.i` @524c8qgv),
/// and 0.9.0 makes max_age one in Rust (@65u2932c), so a test whose subject is something else
/// states that policy rather than relying on it.
fn opted_out() -> VerifyOptions {
    VerifyOptions {
        minimum: Minimum::Off,
        authorities: Authorities::Unchecked,
        expected_keyid: ExpectedKeyid::Unchecked,
        max_age: MaxAge::Unchecked,
        ..Default::default()
    }
}

const URL: &str = "https://api.example.com/things?limit=1";
const BODY: &[u8] = br#"{"hello": "world"}"#;
const AT: i64 = 1_700_000_000;
const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn key() -> Key {
    Key::from_seed(&(0u8..32).collect::<Vec<_>>()).unwrap()
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn strings(specs: &[&str]) -> Vec<String> {
    specs.iter().map(|s| s.to_string()).collect()
}

fn encode(raw: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::new();
    for chunk in raw.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for (i, shift) in [18, 12, 6, 0].iter().enumerate() {
            if i <= chunk.len() {
                out.push(alphabet[(n >> shift) as usize & 63] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

fn cesr(code: char, raw: &[u8]) -> String {
    let mut padded = vec![0u8];
    padded.extend_from_slice(raw);
    format!("{code}{}", &encode(&padded, URL_ALPHABET, false)[1..])
}

/// Bit 4 of the second character lands in the pad byte, so this spells the same 32 bytes.
fn flip_pad_bit(aid: &str) -> String {
    let at = URL_ALPHABET
        .iter()
        .position(|a| *a == aid.as_bytes()[1])
        .unwrap();
    format!(
        "{}{}{}",
        &aid[..1],
        URL_ALPHABET[at ^ 16] as char,
        &aid[2..]
    )
}

/// A signed request as the verifier receives it.
#[derive(Clone, Debug)]
struct Sent {
    method: String,
    url: String,
    body: Option<Vec<u8>>,
    headers: BTreeMap<String, String>,
}

impl Sent {
    fn at(&self, url: &str) -> Sent {
        Sent {
            url: url.into(),
            ..self.clone()
        }
    }

    fn with(&self, name: &str, value: String) -> Sent {
        let mut out = self.clone();
        out.headers.insert(name.into(), value);
        out
    }

    fn verify(&self, opts: VerifyOptions) -> fiki::Result<Verdict> {
        verify_request(
            &self.method,
            &self.url,
            &self.headers,
            &VerifyOptions {
                body: opts.body.clone().or(self.body.clone()),
                now: opts.now.or(Some(AT)),
                ..opts
            },
        )
    }

    fn aid(&self) -> String {
        self.verify(opted_out())
            .unwrap_or_else(|e| panic!("{}: {e}", e.kind))
            .aid
    }

    fn kind(&self, opts: VerifyOptions) -> Kind {
        match self.verify(opts) {
            Ok(verdict) => panic!("accepted: {verdict:?}"),
            Err(e) => e.kind,
        }
    }
}

fn sign(method: &str, url: &str, given: &[(&str, &str)], opts: SignOptions) -> fiki::Result<Sent> {
    let mut headers = map(given);
    let opts = SignOptions {
        created: opts.created.or(Some(AT)),
        ..opts
    };
    headers.extend(sign_request(&key(), method, url, &headers, &opts)?);
    Ok(Sent {
        method: method.into(),
        url: url.into(),
        body: opts.body,
        headers,
    })
}

fn signed() -> Sent {
    sign("GET", URL, &[], SignOptions::default()).unwrap()
}

fn posted() -> Sent {
    sign(
        "POST",
        URL,
        &[],
        SignOptions {
            body: Some(BODY.to_vec()),
            ..Default::default()
        },
    )
    .unwrap()
}

fn kind_of<T: std::fmt::Debug>(result: fiki::Result<T>) -> Kind {
    result.unwrap_err().kind
}

fn params() -> SignatureParams {
    SignatureParams {
        created: Some(AT),
        keyid: Some("k".into()),
        ..Default::default()
    }
}

/// A POST validly signed over a Content-Digest of the caller's spelling, built from the base
/// rather than through sign_request, which refuses to sign a digest it cannot check against the
/// body (A7), so a test can hand the verifier a header the signer would refuse.
fn with_digest(digest: &str) -> Sent {
    let mut headers = map(&[("Content-Digest", digest)]);
    let base = signature_base(
        "POST",
        URL,
        &headers,
        &strings(&["@method", "@authority", "@path", "@query", "content-digest"]),
        &SignatureParams {
            created: Some(AT),
            keyid: Some(key().keyid()),
            alg: Some("ed25519".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let text = String::from_utf8(base.clone()).unwrap();
    let input = text.rsplit_once("\"@signature-params\": ").unwrap().1;
    headers.insert("Signature-Input".into(), format!("sig={input}"));
    headers.insert(
        "Signature".into(),
        format!("sig=:{}:", encode(&key().sign(&base), STD_ALPHABET, true)),
    );
    Sent {
        method: "POST".into(),
        url: URL.into(),
        body: Some(BODY.to_vec()),
        headers,
    }
}

fn authority(url: &str) -> fiki::Result<String> {
    let base = signature_base(
        "GET",
        url,
        &BTreeMap::new(),
        &strings(&["@authority"]),
        &params(),
    )?;
    let text = String::from_utf8(base).unwrap();
    Ok(text
        .lines()
        .next()
        .unwrap()
        .split_once(": ")
        .unwrap()
        .1
        .to_string())
}

fn asked(method: &str, url: &str) -> Request {
    Request {
        method: method.into(),
        url: url.into(),
        ..Default::default()
    }
}

fn recording() -> (Resolver, Arc<Mutex<Vec<String>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = calls.clone();
    let resolver: Resolver = Arc::new(move |keyid: &str| {
        seen.lock().unwrap().push(keyid.to_string());
        Ok(None)
    });
    (resolver, calls)
}

// --- A3: an IP-literal keeps its brackets, and only :port may follow ']' ---

#[test]
fn a3_an_ip_literal_keeps_its_brackets() {
    for (url, expected) in [
        ("https://[2001:db8::1]:8443/x", "[2001:db8::1]:8443"),
        ("https://[2001:DB8::1]/x", "[2001:db8::1]"),
        ("https://[v1.example]:81/x", "[v1.example]:81"),
    ] {
        assert_eq!(authority(url).unwrap(), expected, "{url}");
    }
}

#[test]
fn a3_text_after_an_ip_literal_is_a_caller_error_when_signing() {
    for url in [
        "https://[::1]x/things",
        "https://[::1]:443x/things",
        "https://[::1/things",
        "https://::1]/things",
    ] {
        assert_eq!(kind_of(authority(url)), Kind::InvalidArgument, "{url}");
    }
}

#[test]
fn a3_text_after_an_ip_literal_is_a_signature_mismatch_when_verifying() {
    let sent = sign("GET", "https://[::1]/things", &[], SignOptions::default()).unwrap();
    for url in ["https://[::1]x/things", "https://[::1/things"] {
        assert_eq!(
            sent.at(url).kind(opted_out()),
            Kind::SignatureMismatch,
            "{url}"
        );
    }
}

// The same lists as fiki-py's tests/test_sweep.py, whose oracle is Python's own ipaddress
// (bakobo/fiki#14's hostile pass).
const NOT_ADDRESSES: [&str; 14] = [
    "not-an-ip",
    "1.2.3.4",
    "vZ.x",
    "v1.",
    "V1.x",
    "v.x",
    "::1%",
    "fe80::1%a%b",
    "1:2:3:4:5:6:7:8:9",
    "::01.2.3.4",
    "::256.1.1.1",
    "12345::",
    "",
    "1::2::3",
];

#[test]
fn a3_a_bracketed_host_that_is_not_an_address_is_unreadable() {
    let sent = sign("GET", "https://[::1]/x", &[], SignOptions::default()).unwrap();
    for inside in NOT_ADDRESSES {
        let url = format!("https://[{inside}]/x");
        assert_eq!(kind_of(authority(&url)), Kind::InvalidArgument, "{url}");
        assert_eq!(
            sent.at(&url).kind(opted_out()),
            Kind::SignatureMismatch,
            "{url}"
        );
    }
}

#[test]
fn a3_an_ipv6_address_or_ipvfuture_is_an_ip_literal() {
    for inside in [
        "::1",
        "::",
        "1::",
        "2001:DB8::1",
        "1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7::",
        "::ffff:1.2.3.4",
        "1:2:3:4:5:6:1.2.3.4",
        "fe80::1%25eth0",
        "v1.x",
        "vF.a:b",
        "v12.[",
    ] {
        let url = format!("https://[{inside}]/x");
        assert_eq!(
            authority(&url).unwrap(),
            format!("[{}]", inside.to_ascii_lowercase()),
            "{url}"
        );
    }
}

// --- A4: header names are compared case-insensitively, by presence ---

#[test]
fn a4_two_names_equal_but_for_case_are_a_caller_error_whatever_their_values() {
    // Equal values too: a map that returned the previous value would still see a duplicate, but
    // one that compared values would not, and the rule is presence.
    let both = map(&[("X-A", "1"), ("x-a", "1")]);
    let err = sign_request(&key(), "GET", URL, &both, &SignOptions::default());
    assert_eq!(kind_of(err), Kind::InvalidArgument);
    let err = verify_request("GET", URL, &both, &opted_out());
    assert_eq!(kind_of(err), Kind::InvalidArgument);
}

// --- A7 and E5: a supplied Content-Digest must match the body it is signed with ---

#[test]
fn a7_a_supplied_digest_the_body_does_not_match_is_a_caller_error() {
    let other = content_digest(b"another body");
    for digest in [
        other.as_str(),
        "sha-256=:AAAA:",
        "x-unknown=:AAAA:",
        "not a dictionary (((",
    ] {
        let opts = SignOptions {
            body: Some(BODY.to_vec()),
            ..Default::default()
        };
        let err = sign("POST", URL, &[("Content-Digest", digest)], opts.clone());
        assert_eq!(kind_of(err), Kind::InvalidArgument, "{digest}");
        let err = sign_response(
            &key(),
            200,
            None,
            &map(&[("content-digest", digest)]),
            &opts,
        );
        assert_eq!(kind_of(err), Kind::InvalidArgument, "{digest}");
    }
}

#[test]
fn a7_a_supplied_digest_that_matches_is_signed_as_given() {
    let digest = format!("x-unknown=:AAAA:, {}", content_digest(BODY));
    let opts = SignOptions {
        body: Some(BODY.to_vec()),
        ..Default::default()
    };
    let sent = sign("POST", URL, &[("Content-Digest", &digest)], opts).unwrap();
    assert_eq!(sent.headers["Content-Digest"], digest);
    assert_eq!(sent.aid(), key().aid());
}

// --- A8: Content-Length is trimmed of SP and HTAB only ---

fn under_minimum() -> VerifyOptions {
    VerifyOptions {
        minimum: Minimum::of(REQUEST_MINIMUM),
        ..opted_out()
    }
}

#[test]
fn a8_a_content_length_padded_with_other_whitespace_counts_as_a_body() {
    for length in ["0\u{a0}", "0\u{b}", "0\u{c}", "\u{a0}0"] {
        let sent = sign(
            "GET",
            URL,
            &[("Content-Length", length)],
            SignOptions::default(),
        )
        .unwrap();
        assert_eq!(
            sent.kind(under_minimum()),
            Kind::InsufficientCoverage,
            "{length:?}"
        );
    }
}

#[test]
fn a8_a_content_length_padded_with_sp_and_htab_is_still_zero() {
    let sent = sign(
        "GET",
        URL,
        &[("Content-Length", " \t0\t ")],
        SignOptions::default(),
    )
    .unwrap();
    assert_eq!(sent.verify(under_minimum()).unwrap().aid, key().aid());
}

// --- A10: keyid well-formedness, then the expected keyid, then the resolver ---

fn signed_as(keyid: &str) -> Sent {
    sign(
        "GET",
        URL,
        &[],
        SignOptions {
            keyid: Some(keyid.into()),
            ..Default::default()
        },
    )
    .unwrap()
}

fn expecting(keyid: &str) -> VerifyOptions {
    VerifyOptions {
        expected_keyid: ExpectedKeyid::is(keyid),
        ..opted_out()
    }
}

#[test]
fn a10_a_malformed_raw_keyid_beside_an_expected_keyid_is_malformed_not_unknown() {
    let sent = signed_as("not-a-key");
    assert_eq!(sent.kind(expecting(&key().keyid())), Kind::MalformedKey);
}

#[test]
fn a10_a_small_order_raw_keyid_beside_an_expected_keyid_is_malformed_not_unknown() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let sent = signed_as(&encode(&identity, URL_ALPHABET, false));
    assert_eq!(sent.kind(expecting(&key().keyid())), Kind::MalformedKey);
}

#[test]
fn a10_a_misspelled_aid_beside_an_expected_keyid_is_malformed_and_never_resolved() {
    let aid = cesr('E', &[7u8; 32]);
    let sent = signed_as(&flip_pad_bit(&aid));
    let (resolver, calls) = recording();
    let opts = VerifyOptions {
        resolve: Some(resolver),
        ..expecting(&aid)
    };
    assert_eq!(sent.kind(opts), Kind::MalformedKey);
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn a10_an_unexpected_keyid_is_unknown_without_asking_the_resolver() {
    let sent = signed_as(&cesr('E', &[7u8; 32]));
    let (resolver, calls) = recording();
    let opts = VerifyOptions {
        resolve: Some(resolver),
        ..expecting(&format!("E{}", "A".repeat(43)))
    };
    assert_eq!(sent.kind(opts), Kind::UnknownKey);
    assert!(calls.lock().unwrap().is_empty());
}

// --- A11: a 401 whose Signature header is empty is an unsigned 401 ---

#[test]
fn a11_a_401_with_an_empty_signature_header_is_unauthenticated() {
    for headers in [
        map(&[("Signature", "")]),
        map(&[("Signature", ""), ("Signature-Input", "sig=()")]),
    ] {
        let err = verify_response(401, &headers, None, &opted_out());
        assert_eq!(kind_of(err), Kind::Unauthenticated);
    }
}

// --- A12: RFC 8941 parsing is strict ---

#[test]
fn a12_a_decimal_without_a_fractional_digit_is_malformed() {
    for member in ["x=1.", "x=-1.", "x=1.;a=2", "x=(1.)", "x=2;a=1."] {
        let sent = with_digest(&format!("{}, {member}", content_digest(BODY)));
        assert_eq!(sent.kind(opted_out()), Kind::MalformedDigest, "{member}");
    }
}

#[test]
fn a12_what_only_looks_like_a_bare_decimal_is_still_accepted() {
    for member in ["x=1.5", "x=\"1.\"", "x=a1.", "x=*1.", "x=:QUFB:", "x=a:1."] {
        let sent = with_digest(&format!("{}, {member}", content_digest(BODY)));
        assert_eq!(sent.aid(), key().aid(), "{member}");
    }
}

#[test]
fn a12_a_bare_decimal_is_malformed_in_the_other_two_headers() {
    let sent = signed();
    let bad = sent.with("Signature", format!("{};x=1.", sent.headers["Signature"]));
    assert_eq!(bad.kind(opted_out()), Kind::MalformedSignature);
    let bad = sent.with(
        "Signature-Input",
        format!("{};x=1.", sent.headers["Signature-Input"]),
    );
    assert_eq!(bad.kind(opted_out()), Kind::MalformedSignatureInput);
}

#[test]
fn a12_long_integers_and_badly_padded_byte_sequences_are_malformed() {
    for member in [
        "x=1234567890123456",
        "x=:QQ:",
        "x=:QQ=:",
        "x=:=:",
        "x=:QQ==QQ==:",
    ] {
        let sent = with_digest(&format!("{}, {member}", content_digest(BODY)));
        assert_eq!(sent.kind(opted_out()), Kind::MalformedDigest, "{member:?}");
    }
}

#[test]
fn a12_trailing_ows_after_a_dictionary_member_is_accepted() {
    let sent = signed();
    let sent = sent.with("Signature", format!("{} \t", sent.headers["Signature"]));
    assert_eq!(sent.aid(), key().aid());
}

// --- B13: the method is a token, on every path ---

#[test]
fn b13_a_method_that_is_not_a_token_is_a_caller_error_wherever_a_request_is_built() {
    let good = signed();
    for method in ["", " ", "G T", "GET\r\n", "GET\n", "G(T", "caf\u{e9}"] {
        let covering_path = SignOptions {
            covered: Some(strings(&["@path"])),
            ..Default::default()
        };
        let err = sign(method, URL, &[], covering_path);
        assert_eq!(kind_of(err), Kind::InvalidArgument, "{method:?}");
        let err = signature_base(
            method,
            URL,
            &BTreeMap::new(),
            &strings(&["@path"]),
            &params(),
        );
        assert_eq!(kind_of(err), Kind::InvalidArgument, "{method:?}");
        let sent = Sent {
            method: method.into(),
            ..good.clone()
        };
        assert_eq!(sent.kind(opted_out()), Kind::InvalidArgument, "{method:?}");
        let request = asked(method, URL);
        let err = response_signature_base(
            200,
            &BTreeMap::new(),
            Some(&request),
            &strings(&["@status"]),
            &params(),
        );
        assert_eq!(kind_of(err), Kind::InvalidArgument, "{method:?}");
        let err = verify_response(200, &BTreeMap::new(), Some(&request), &opted_out());
        assert_eq!(kind_of(err), Kind::InvalidArgument, "{method:?}");
        let err = sign_response(
            &key(),
            200,
            Some(&request),
            &BTreeMap::new(),
            &SignOptions::default(),
        );
        assert_eq!(kind_of(err), Kind::InvalidArgument, "{method:?}");
    }
}

#[test]
fn b13_any_token_is_a_method_and_keeps_its_case() {
    for method in ["M-SEARCH", "get", "PROPFIND", "x!#$%&'*+.^_`|~1"] {
        let sent = sign(method, URL, &[], SignOptions::default()).unwrap();
        assert_eq!(sent.aid(), key().aid(), "{method}");
        let base = signature_base(
            method,
            URL,
            &BTreeMap::new(),
            &strings(&["@method"]),
            &params(),
        )
        .unwrap();
        let text = String::from_utf8(base).unwrap();
        assert!(
            text.starts_with(&format!("\"@method\": {method}\n")),
            "{text}"
        );
    }
}

// --- B14 and E2: a port is a run of ASCII digits, read as a number, in 0..65535 ---

#[test]
fn b14_a_port_is_read_as_a_number() {
    let padded = format!("https://a.example:{}8443/x", "0".repeat(200));
    for (url, expected) in [
        ("http://a.example:000080/x", "a.example"),
        ("https://a.example:0443/x", "a.example"),
        ("https://a.example:08443/x", "a.example:8443"),
        (padded.as_str(), "a.example:8443"),
        ("https://a.example:65535/x", "a.example:65535"),
        ("https://a.example:0/x", "a.example:0"),
        ("https://a.example:/x", "a.example"),
        ("https://A.example:81/x", "a.example:81"),
    ] {
        assert_eq!(authority(url).unwrap(), expected, "{url}");
    }
}

const BAD_PORTS: [&str; 10] = [
    "65536",
    "99999",
    "8x",
    "+80",
    " 80",
    "-1",
    "\u{668}\u{660}",
    "80 ",
    "0x50",
    "1e3",
];

#[test]
fn b14_a_port_that_is_not_one_is_a_caller_error_when_signing() {
    for port in BAD_PORTS {
        let url = format!("https://a.example:{port}/x");
        assert_eq!(kind_of(authority(&url)), Kind::InvalidArgument, "{port:?}");
        let err = sign("GET", &url, &[], SignOptions::default());
        assert_eq!(kind_of(err), Kind::InvalidArgument, "{port:?}");
    }
}

#[test]
fn b14_a_port_that_is_not_one_is_a_signature_mismatch_when_verifying() {
    let sent = sign("GET", "https://a.example/x", &[], SignOptions::default()).unwrap();
    for port in BAD_PORTS {
        let url = format!("https://a.example:{port}/x");
        assert_eq!(
            sent.at(&url).kind(opted_out()),
            Kind::SignatureMismatch,
            "{port:?}"
        );
    }
}

#[test]
fn b14_a_bad_port_is_a_signature_mismatch_in_the_request_a_response_answers() {
    let opts = SignOptions {
        created: Some(AT),
        covered: Some(vec!["@status".into(), req("@authority")]),
        ..Default::default()
    };
    let headers = sign_response(
        &key(),
        200,
        Some(&asked("GET", "https://a.example/x")),
        &BTreeMap::new(),
        &opts,
    )
    .unwrap();
    let err = verify_response(
        200,
        &headers,
        Some(&asked("GET", "https://a.example:99999/x")),
        &VerifyOptions {
            now: Some(AT),
            ..opted_out()
        },
    );
    assert_eq!(kind_of(err), Kind::SignatureMismatch);
}

#[test]
fn b14_a_bad_port_is_never_read_when_authority_is_not_covered() {
    let opts = SignOptions {
        covered: Some(strings(&["@method", "@path", "@query"])),
        ..Default::default()
    };
    let sent = sign("GET", "https://a.example/x", &[], opts).unwrap();
    assert_eq!(sent.at("https://a.example:99999/x").aid(), key().aid());
}

// --- B15: what the signer serializes must be serializable ---

#[test]
fn b15_a_label_that_is_not_an_rfc_8941_key_is_a_caller_error() {
    for label in ["a\r\nb", "Sig", "1sig", "", "si g", "sig\u{e9}", "-a"] {
        let opts = SignOptions {
            label: Some(label.into()),
            ..Default::default()
        };
        let err = sign("GET", URL, &[], opts.clone());
        assert_eq!(kind_of(err), Kind::InvalidArgument, "{label:?}");
        let err = sign_response(&key(), 200, None, &BTreeMap::new(), &opts);
        assert_eq!(kind_of(err), Kind::InvalidArgument, "{label:?}");
    }
}

#[test]
fn b15_any_rfc_8941_key_is_a_label() {
    for label in ["sig", "*", "a1_.-*", "signify"] {
        let opts = SignOptions {
            label: Some(label.into()),
            ..Default::default()
        };
        let sent = sign("GET", URL, &[], opts).unwrap();
        assert!(sent.headers["Signature"].starts_with(&format!("{label}=:")));
        assert_eq!(sent.aid(), key().aid(), "{label}");
    }
}

#[test]
fn b15_a_serialized_string_outside_printable_ascii_is_a_caller_error() {
    for value in ["a\r\nb", "a\nb", "caf\u{e9}", "a\u{7f}", "a\tb", "\0"] {
        for field in ["keyid", "nonce", "tag"] {
            let text = Some(value.to_string());
            let opts = match field {
                "keyid" => SignOptions {
                    keyid: text.clone(),
                    ..Default::default()
                },
                "nonce" => SignOptions {
                    nonce: text.clone(),
                    ..Default::default()
                },
                _ => SignOptions {
                    tag: text.clone(),
                    ..Default::default()
                },
            };
            let err = sign("GET", URL, &[], opts);
            assert_eq!(kind_of(err), Kind::InvalidArgument, "{field} {value:?}");
            let mut base_params = params();
            match field {
                "keyid" => base_params.keyid = text,
                "nonce" => base_params.nonce = text,
                _ => base_params.tag = text,
            }
            let err = signature_base(
                "GET",
                URL,
                &BTreeMap::new(),
                &strings(&["@path"]),
                &base_params,
            );
            assert_eq!(kind_of(err), Kind::InvalidArgument, "{field} {value:?}");
            let err = response_signature_base(
                200,
                &BTreeMap::new(),
                None,
                &strings(&["@status"]),
                &base_params,
            );
            assert_eq!(kind_of(err), Kind::InvalidArgument, "{field} {value:?}");
        }
    }
    // alg is serialized as an sf-string too.
    let err = signature_base(
        "GET",
        URL,
        &BTreeMap::new(),
        &strings(&["@path"]),
        &SignatureParams {
            alg: Some("ed\n25519".into()),
            ..params()
        },
    );
    assert_eq!(kind_of(err), Kind::InvalidArgument);
}

#[test]
fn b15_every_printable_ascii_character_is_a_serializable_string() {
    let value: String = (0x20u8..0x7f).map(char::from).collect();
    for opts in [
        SignOptions {
            nonce: Some(value.clone()),
            ..Default::default()
        },
        SignOptions {
            tag: Some(value.clone()),
            ..Default::default()
        },
    ] {
        let sent = sign("GET", URL, &[], opts).unwrap();
        assert_eq!(sent.aid(), key().aid());
    }
}

#[test]
fn b15_a_component_name_that_is_not_a_field_name_is_a_caller_error() {
    for name in ["x\r\ny", "a b", "", "x:y", "caf\u{e9}", "x\t"] {
        let given: Vec<(&str, &str)> = if name.is_empty() {
            vec![]
        } else {
            vec![(name, "1")]
        };
        let opts = SignOptions {
            covered: Some(strings(&["@method", name])),
            ..Default::default()
        };
        let err = sign("GET", URL, &given, opts);
        assert_eq!(kind_of(err), Kind::InvalidArgument, "{name:?}");
    }
}

#[test]
fn b15_a_serialized_component_whose_name_is_not_a_field_name_is_a_caller_error() {
    let opts = SignOptions {
        covered: Some(strings(&["\"a b\""])),
        ..Default::default()
    };
    assert_eq!(kind_of(sign("GET", URL, &[], opts)), Kind::InvalidArgument);
    let opts = SignOptions {
        covered: Some(strings(&["@status", "\"a b\";req"])),
        ..Default::default()
    };
    let err = sign_response(
        &key(),
        200,
        Some(&asked("GET", URL)),
        &BTreeMap::new(),
        &opts,
    );
    assert_eq!(kind_of(err), Kind::InvalidArgument);
}

#[test]
fn b15_an_unknown_derived_component_keeps_its_own_refusal() {
    let opts = SignOptions {
        covered: Some(strings(&["@target-uri"])),
        ..Default::default()
    };
    assert_eq!(
        kind_of(sign("GET", URL, &[], opts)),
        Kind::UnsupportedComponent
    );
}

#[test]
fn b15_a_field_name_is_still_lowercased_for_a_local_caller() {
    let opts = SignOptions {
        covered: Some(strings(&["@method", "X-Role"])),
        ..Default::default()
    };
    let sent = sign("GET", URL, &[("X-Role", "admin")], opts).unwrap();
    assert!(sent.headers["Signature-Input"].contains("\"x-role\""));
    let verdict = sent.verify(opted_out()).unwrap();
    assert_eq!(verdict.covered, ["@method", "x-role"]);
}

// --- B16: created and expires fit RFC 8941's integer range ---

#[test]
fn b16_a_timestamp_outside_the_integer_range_is_a_caller_error() {
    for value in [1_000_000_000_000_000, -1, i64::MAX, i64::MIN] {
        for created in [true, false] {
            let opts = if created {
                SignOptions {
                    created: Some(value),
                    ..Default::default()
                }
            } else {
                SignOptions {
                    expires: Some(value),
                    ..Default::default()
                }
            };
            let err = sign("GET", URL, &[], opts);
            assert_eq!(kind_of(err), Kind::InvalidArgument, "{value} {created}");
            let mut base_params = params();
            if created {
                base_params.created = Some(value);
            } else {
                base_params.expires = Some(value);
            }
            let err = signature_base(
                "GET",
                URL,
                &BTreeMap::new(),
                &strings(&["@path"]),
                &base_params,
            );
            assert_eq!(kind_of(err), Kind::InvalidArgument, "{value} {created}");
        }
    }
}

#[test]
fn b16_the_largest_and_smallest_timestamps_are_signed() {
    let opts = SignOptions {
        created: Some(0),
        expires: Some(999_999_999_999_999),
        ..Default::default()
    };
    // sign() fills created only when it is None, so 0 survives.
    let sent = sign("GET", URL, &[], opts).unwrap();
    assert!(sent.headers["Signature-Input"].contains("created=0;expires=999999999999999"));
    assert_eq!(sent.aid(), key().aid());
}

// --- B17: max_age and skew are positive when given ---

#[test]
fn b17_a_freshness_window_that_is_not_positive_is_a_caller_error() {
    let sent = signed();
    for value in [0, -1, i64::MIN] {
        for opts in [
            VerifyOptions {
                max_age: MaxAge::seconds(value),
                ..opted_out()
            },
            VerifyOptions {
                skew: Some(value),
                ..opted_out()
            },
        ] {
            assert_eq!(sent.kind(opts.clone()), Kind::InvalidArgument, "{value}");
            let err = verify_response(200, &BTreeMap::new(), None, &opts);
            assert_eq!(kind_of(err), Kind::InvalidArgument, "{value}");
        }
    }
}

#[test]
fn b17_enormous_windows_neither_overflow_nor_refuse() {
    let opts = SignOptions {
        expires: Some(999_999_999_999_999),
        ..Default::default()
    };
    let sent = sign("GET", URL, &[], opts).unwrap();
    let verdict = sent.verify(VerifyOptions {
        max_age: MaxAge::seconds(i64::MAX),
        skew: Some(i64::MAX),
        now: Some(1_000_000_000_000_000_000),
        ..opted_out()
    });
    assert_eq!(verdict.unwrap().aid, key().aid());
    // And at the other end of the clock, where now - created is the subtraction that wraps: compared
    // rather than overflowed, created is further in the future than even this skew allows.
    let refused = sent.verify(VerifyOptions {
        max_age: MaxAge::seconds(i64::MAX),
        skew: Some(i64::MAX),
        now: Some(i64::MIN),
        ..opted_out()
    });
    assert_eq!(kind_of(refused), Kind::SignatureTooOld);
}

// --- B18: Verdict.keyid is the wire keyid; Verdict.aid is who vouched ---

#[test]
fn b18_the_verdict_keyid_is_the_wire_keyid_and_the_aid_is_who_vouched() {
    let verdict = signed().verify(opted_out()).unwrap();
    assert_eq!(
        (verdict.keyid, verdict.aid),
        (Some(key().keyid()), key().aid())
    );
    let verdict = signed_as("any keyid at all")
        .verify(VerifyOptions {
            expected_aid: Some(key().aid()),
            ..opted_out()
        })
        .unwrap();
    assert_eq!(
        (verdict.keyid, verdict.aid),
        (Some("any keyid at all".to_string()), key().aid())
    );
}

#[test]
fn b18_the_verdict_documents_both_fields() {
    let source = include_str!("../src/messages.rs");
    let at = source.find("pub struct Verdict").unwrap();
    let doc: String = source[..at]
        .lines()
        .rev()
        .take_while(|line| line.starts_with("///") || line.starts_with("#["))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|line| line.trim_start_matches("///").trim())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(doc.contains("exactly as it appeared on the wire"), "{doc}");
    assert!(doc.contains("`None` when the signature had none"), "{doc}");
    assert!(
        doc.contains("the identity that vouched for the key"),
        "{doc}"
    );
}

// --- B19: both format numbers are exported ---

#[test]
fn b19_both_vectors_formats_are_exported() {
    let formats: [u32; 2] = [fiki::VECTORS_FORMAT, fiki::KERI_VECTORS_FORMAT];
    assert_eq!(formats, [3, 5]);
}

// --- B20: input bounds, size before shape ---

/// Trailing spaces an RFC 8941 parser discards, so only the size check can refuse it.
fn pad_to(value: &str, size: usize) -> String {
    format!("{value}{}", " ".repeat(size - value.len()))
}

#[test]
fn b20_a_field_over_8192_bytes_is_malformed_before_it_is_parsed() {
    for (header, kind) in [
        ("Signature", Kind::MalformedSignature),
        ("Signature-Input", Kind::MalformedSignatureInput),
        ("Content-Digest", Kind::MalformedDigest),
    ] {
        let sent = posted();
        let sent = sent.with(header, pad_to(&sent.headers[header], 8193));
        let err = sent.verify(opted_out()).unwrap_err();
        assert_eq!(err.kind, kind, "{header}");
        assert!(err.message.contains("8192"), "{}", err.message);
    }
}

#[test]
fn b20_a_field_over_8192_bytes_is_refused_whatever_it_holds() {
    let sent = posted();
    for value in ["(".repeat(9000), "\u{e9}".repeat(4097)] {
        let err = sent
            .with("Signature-Input", value)
            .verify(opted_out())
            .unwrap_err();
        assert_eq!(err.kind, Kind::MalformedSignatureInput);
        assert!(err.message.contains("8192"), "{}", err.message);
    }
}

#[test]
fn b20_a_field_of_exactly_8192_bytes_is_read() {
    for header in ["Signature", "Signature-Input", "Content-Digest"] {
        let sent = posted();
        let sent = sent.with(header, pad_to(&sent.headers[header], 8192));
        assert_eq!(sent.aid(), key().aid(), "{header}");
    }
}

fn extra_members(n: usize) -> String {
    (0..n).map(|i| format!(", x{i}=:AAAA:")).collect()
}

#[test]
fn b20_a_dictionary_of_seventeen_members_is_malformed() {
    let sent = posted();
    let bad = sent.with(
        "Signature",
        format!("{}{}", sent.headers["Signature"], extra_members(16)),
    );
    assert_eq!(bad.kind(opted_out()), Kind::MalformedSignature);
    let bad = sent.with(
        "Signature-Input",
        format!("{}{}", sent.headers["Signature-Input"], extra_members(16)),
    );
    assert_eq!(bad.kind(opted_out()), Kind::MalformedSignatureInput);
    let bad = with_digest(&format!("{}{}", content_digest(BODY), extra_members(16)));
    assert_eq!(bad.kind(opted_out()), Kind::MalformedDigest);
}

#[test]
fn b20_a_dictionary_of_sixteen_members_is_read() {
    let sent = posted();
    let bad = sent.with(
        "Signature",
        format!("{}{}", sent.headers["Signature"], extra_members(15)),
    );
    assert_eq!(bad.kind(opted_out()), Kind::MalformedSignatureLabel);
    let good = with_digest(&format!("{}{}", content_digest(BODY), extra_members(15)));
    assert_eq!(good.aid(), key().aid());
}

#[test]
fn b20_an_inner_list_of_sixty_four_components_is_read_and_sixty_five_is_malformed() {
    let fields: Vec<(String, String)> = (0..62)
        .map(|i| (format!("x-h{i}"), i.to_string()))
        .collect();
    let given: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut covered = strings(&["@method", "@path", "@query"]);
    covered.extend(fields.iter().map(|(k, _)| k.clone()));
    let opts = SignOptions {
        covered: Some(covered[..64].to_vec()),
        ..Default::default()
    };
    let sent = sign("GET", URL, &given, opts).unwrap();
    assert_eq!(sent.verify(opted_out()).unwrap().covered.len(), 64);
    let opts = SignOptions {
        covered: Some(covered),
        ..Default::default()
    };
    let sent = sign("GET", URL, &given, opts).unwrap();
    assert_eq!(sent.kind(opted_out()), Kind::MalformedSignatureInput);
}

#[test]
fn b20_an_inner_list_anywhere_holds_at_most_sixty_four_items() {
    let ones = vec!["1"; 65].join(" ");
    let sent = with_digest(&format!("{}, x=({ones})", content_digest(BODY)));
    assert_eq!(sent.kind(opted_out()), Kind::MalformedDigest);
}

fn many_params(n: usize) -> String {
    (0..n).map(|i| format!(";p{i}")).collect()
}

#[test]
fn b20_an_item_with_seventeen_parameters_is_malformed() {
    let sent = posted();
    let input = &sent.headers["Signature-Input"];
    let bad = sent.with(
        "Signature-Input",
        input.replace("\"@path\"", &format!("\"@path\"{}", many_params(17))),
    );
    assert_eq!(bad.kind(opted_out()), Kind::MalformedSignatureInput);
    let bad = sent.with(
        "Signature",
        format!("{}{}", sent.headers["Signature"], many_params(17)),
    );
    assert_eq!(bad.kind(opted_out()), Kind::MalformedSignature);
    let bad = with_digest(&format!("{}{}", content_digest(BODY), many_params(17)));
    assert_eq!(bad.kind(opted_out()), Kind::MalformedDigest);
    let bad = sent.with("Signature-Input", format!("{input}{}", many_params(17)));
    assert_eq!(bad.kind(opted_out()), Kind::MalformedSignatureInput);
}

#[test]
fn b20_an_item_with_sixteen_parameters_is_read() {
    let sent = with_digest(&format!("{}{}", content_digest(BODY), many_params(16)));
    assert_eq!(sent.aid(), key().aid());
}

#[test]
fn b20_the_bounds_are_exported_constants() {
    assert_eq!(
        [
            fiki::MAX_FIELD_BYTES,
            fiki::MAX_DICTIONARY_MEMBERS,
            fiki::MAX_INNER_LIST_ITEMS,
            fiki::MAX_PARAMETERS
        ],
        [8192, 16, 64, 16]
    );
}

// --- the spec's open item, ruled by the conductor: a URL is read as Python's urlsplit reads it ---

fn line_of(component: &str, url: &str) -> String {
    let base = signature_base(
        "GET",
        url,
        &BTreeMap::new(),
        &strings(&[component]),
        &params(),
    )
    .unwrap();
    let text = String::from_utf8(base).unwrap();
    text.lines()
        .next()
        .unwrap()
        .split_once(": ")
        .unwrap()
        .1
        .to_string()
}

// Format 3 reverses the stripping these tests once pinned (@2n99rej7): a space or an ASCII
// control anywhere in a target is refused rather than stripped, so "/\nx" is never read as "/x"
// (`this.i` @524c8qgv, "A target beginning with a slash is origin-form"). Their subject was the
// stripping itself, so their expectation changes rather than their policy.

#[test]
fn e_tab_cr_and_lf_anywhere_in_a_url_are_refused() {
    for url in [
        "https://a.exa\tmple:8\r\n443/x",
        "https://a.example/a\r\nb\tc",
        "https://a.example/x?a=\n1",
        "/a\nb",
    ] {
        assert_eq!(kind_of(authority(url)), Kind::InvalidArgument, "{url:?}");
    }
    assert_eq!(line_of("@path", "https://a.example/abc"), "/abc");
}

#[test]
fn e_leading_and_trailing_c0_controls_and_spaces_are_refused() {
    for url in [
        "\u{0}\u{1f} https://a.example/x",
        " \u{b}https://a.example/x ",
        "https://a.example/x\u{b}",
        "https://a.example/x\u{7f}",
    ] {
        let err = signature_base(
            "GET",
            url,
            &BTreeMap::new(),
            &strings(&["@path"]),
            &params(),
        );
        assert_eq!(kind_of(err), Kind::InvalidArgument, "{url:?}");
    }
}

#[test]
fn e_a_url_with_whitespace_does_not_verify_as_the_url_it_was_signed_as() {
    let sent = signed();
    let dirty = format!(" {}", URL.replacen("api", "a\tp\ni", 1));
    assert_eq!(sent.at(&dirty).kind(opted_out()), Kind::SignatureMismatch);
}

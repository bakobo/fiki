//! What the KERI profile of RFC 9421 asks of a signer and verifier beyond the shared vectors
//! (`this.i` @7f28p7xk, @2f227n4r, @7p9s3g9k, @6g9zjsv9, @5e2phpjy).
//!
//! The port of fiki-py's `py/tests/test_profile.py`: every-digest matching, caller-chosen keyids
//! with an authoritative resolver, responses bound to their request with `req`, the wire-side
//! refusals, an optional minimum covered set, and the profile's section 9 refusal order. The KERI
//! vectors pin each of these once with one defect per case; these pin the edges and the orders the
//! vectors cannot show with one defect. Where Rust's types make one of py's cases unrepresentable —
//! a resolver returning the wrong number of bytes, a status that is not an integer — the case is
//! absent here and @5e2phpjy says why.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use fiki::{
    content_digest, req, response_signature_base, sign_request, sign_response, signature_base,
    verify_request, verify_response, verifying_key, Error, Key, Kind, Request, Resolver,
    SignOptions, SignatureParams, Verdict, VerifyOptions, REQUEST_MINIMUM, RESPONSE_MINIMUM,
};
use sha2::{Digest, Sha256, Sha512};

const URL: &str = "https://keria.example.com/identifiers?type=rot";
const BODY: &[u8] = br#"{"hello": "world"}"#;
const RESPONSE_BODY: &[u8] = br#"{"done": true}"#;
const AT: i64 = 1_700_000_000;
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn key() -> Key {
    Key::from_seed(&(0u8..32).collect::<Vec<_>>()).unwrap()
}

fn other() -> Key {
    Key::from_seed(&(1u8..33).collect::<Vec<_>>()).unwrap()
}

fn raw(key: &Key) -> [u8; 32] {
    *verifying_key(&key.aid()).unwrap().as_bytes()
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

/// A 44-character qb64 over 32 raw bytes, the arithmetic fiki's own B lens uses.
fn cesr(code: char, raw: &[u8]) -> String {
    let mut padded = vec![0u8];
    padded.extend_from_slice(raw);
    format!("{code}{}", &encode(&padded, B64URL, false)[1..])
}

fn aid() -> String {
    cesr('E', &Sha256::digest(b"a transferable AID"))
}

/// The same 32 key bytes, spelled with a non-zero bit in the pad byte the code character replaces.
fn padding_bit_alias(aid: &str) -> String {
    let value = B64URL.iter().position(|a| *a == aid.as_bytes()[1]).unwrap();
    format!(
        "{}{}{}",
        &aid[..1],
        B64URL[value ^ 0b010000] as char,
        &aid[2..]
    )
}

fn strings(specs: &[&str]) -> Vec<String> {
    specs.iter().map(|s| s.to_string()).collect()
}

fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn table(pairs: &[(&str, [u8; 32])]) -> Resolver {
    let known: BTreeMap<String, [u8; 32]> =
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    Arc::new(move |keyid: &str| Ok(known.get(keyid).copied()))
}

/// A request as a verifier sees it: what was signed, plus the headers it went out with.
#[derive(Debug)]
struct Sent {
    method: String,
    url: String,
    body: Option<Vec<u8>>,
    headers: BTreeMap<String, String>,
}

impl Sent {
    fn mangle(mut self, old: &str, new: &str) -> Self {
        let input = self.headers["Signature-Input"].clone();
        assert!(input.contains(old), "{old} is not in {input}");
        self.headers
            .insert("Signature-Input".into(), input.replace(old, new));
        self
    }

    fn keyid(&self) -> String {
        let input = &self.headers["Signature-Input"];
        input
            .split("keyid=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_string()
    }

    fn verify(&self, opts: VerifyOptions) -> fiki::Result<Verdict> {
        verify_request(
            &self.method,
            &self.url,
            &self.headers,
            &VerifyOptions {
                body: self.body.clone(),
                ..opts
            },
        )
    }

    fn kind(&self, opts: VerifyOptions) -> Kind {
        self.verify(opts).unwrap_err().kind
    }
}

fn sign_as(
    signer: &Key,
    method: &str,
    url: &str,
    extra: &[(&str, &str)],
    opts: SignOptions,
) -> fiki::Result<Sent> {
    let given = headers(extra);
    let opts = SignOptions {
        created: opts.created.or(Some(AT)),
        ..opts
    };
    let mut all = given.clone();
    all.extend(sign_request(signer, method, url, &given, &opts)?);
    Ok(Sent {
        method: method.into(),
        url: url.into(),
        body: opts.body,
        headers: all,
    })
}

fn signed(opts: SignOptions) -> Sent {
    sign_as(&key(), "POST", URL, &[], with_body(opts)).unwrap()
}

fn with_body(opts: SignOptions) -> SignOptions {
    SignOptions {
        body: opts.body.or(Some(BODY.to_vec())),
        ..opts
    }
}

fn bodiless(extra: &[(&str, &str)], opts: SignOptions) -> Sent {
    sign_as(&key(), "POST", URL, extra, opts).unwrap()
}

fn covering(specs: &[&str]) -> SignOptions {
    SignOptions {
        covered: Some(strings(specs)),
        ..Default::default()
    }
}

fn minimum(specs: &[&str]) -> VerifyOptions {
    VerifyOptions {
        minimum: Some(strings(specs)),
        ..Default::default()
    }
}

fn resolving(resolver: Resolver) -> VerifyOptions {
    VerifyOptions {
        resolve: Some(resolver),
        ..Default::default()
    }
}

fn request() -> Request {
    Request {
        method: "POST".into(),
        url: URL.into(),
        headers: headers(&[("Content-Digest", &content_digest(BODY))]),
        body: Some(BODY.to_vec()),
    }
}

fn respond_to(
    asked: Option<&Request>,
    extra: &[(&str, &str)],
    opts: SignOptions,
) -> fiki::Result<BTreeMap<String, String>> {
    let given = headers(extra);
    let opts = SignOptions {
        created: opts.created.or(Some(AT)),
        ..opts
    };
    let mut all = given.clone();
    all.extend(sign_response(&key(), 200, asked, &given, &opts)?);
    Ok(all)
}

fn respond(opts: SignOptions) -> BTreeMap<String, String> {
    let opts = SignOptions {
        body: opts.body.or(Some(RESPONSE_BODY.to_vec())),
        ..opts
    };
    respond_to(Some(&request()), &[], opts).unwrap()
}

fn check_as(
    status: u16,
    headers: &BTreeMap<String, String>,
    asked: Option<&Request>,
    body: Option<&[u8]>,
    opts: VerifyOptions,
) -> fiki::Result<Verdict> {
    verify_response(
        status,
        headers,
        asked,
        &VerifyOptions {
            body: body.map(<[u8]>::to_vec),
            ..opts
        },
    )
}

fn check(headers: &BTreeMap<String, String>, opts: VerifyOptions) -> fiki::Result<Verdict> {
    check_as(200, headers, Some(&request()), Some(RESPONSE_BODY), opts)
}

fn mangled(
    mut headers: BTreeMap<String, String>,
    old: &str,
    new: &str,
) -> BTreeMap<String, String> {
    let input = headers["Signature-Input"].clone();
    assert!(input.contains(old), "{old} is not in {input}");
    headers.insert("Signature-Input".into(), input.replace(old, new));
    headers
}

fn kind_of<T: std::fmt::Debug>(result: fiki::Result<T>) -> Kind {
    result.unwrap_err().kind
}

// --- Content-Digest: every recognized member must match (RFC 9530) ---

#[test]
fn two_recognized_digests_must_both_match() {
    let bad512 = encode(&Sha512::digest(b"other"), B64STD, true);
    let digest = format!("{}, sha-512=:{bad512}:", content_digest(BODY));
    let sent = sign_as(
        &key(),
        "POST",
        URL,
        &[("Content-Digest", &digest)],
        with_body(SignOptions::default()),
    )
    .unwrap();
    assert_eq!(sent.kind(VerifyOptions::default()), Kind::DigestMismatch);
}

#[test]
fn two_recognized_digests_that_both_match_verify() {
    let good512 = encode(&Sha512::digest(BODY), B64STD, true);
    let digest = format!("sha-512=:{good512}:, {}", content_digest(BODY));
    let sent = sign_as(
        &key(),
        "POST",
        URL,
        &[("Content-Digest", &digest)],
        with_body(SignOptions::default()),
    )
    .unwrap();
    assert_eq!(
        sent.verify(VerifyOptions::default()).unwrap().aid,
        key().aid()
    );
}

#[test]
fn an_unparsable_digest_is_malformed_even_when_no_body_was_supplied() {
    // Section 9 puts malformed-digest before digest-mismatch.
    let mut sent = sign_as(
        &key(),
        "POST",
        URL,
        &[("Content-Digest", "((((")],
        with_body(SignOptions::default()),
    )
    .unwrap();
    sent.body = None;
    assert_eq!(sent.kind(VerifyOptions::default()), Kind::MalformedDigest);
}

// --- caller-chosen keyid and an authoritative resolver (@6g9zjsv9) ---

fn under_aid() -> SignOptions {
    SignOptions {
        keyid: Some(aid()),
        ..Default::default()
    }
}

#[test]
fn a_caller_may_sign_with_an_aid_as_the_keyid() {
    let sent = signed(under_aid());
    assert!(sent.headers["Signature-Input"].contains(&format!("keyid=\"{}\"", aid())));
}

#[test]
fn a_resolver_supplies_the_key_for_a_transferable_aid() {
    let verdict = signed(under_aid())
        .verify(resolving(table(&[(&aid(), raw(&key()))])))
        .unwrap();
    assert_eq!(verdict.aid, aid());
    assert_eq!(verdict.keyid, Some(aid()));
}

#[test]
fn without_a_resolver_the_verdict_still_reports_the_raw_keyid() {
    let verdict = signed(SignOptions::default())
        .verify(VerifyOptions::default())
        .unwrap();
    assert_eq!(verdict.aid, key().aid());
    assert_eq!(verdict.keyid, Some(encode(&raw(&key()), B64URL, false)));
}

#[test]
fn a_keyid_the_resolver_does_not_know_is_an_unknown_key() {
    let err = signed(under_aid())
        .verify(resolving(table(&[])))
        .unwrap_err();
    assert_eq!(err.kind, Kind::UnknownKey);
    assert_eq!(err.detail, Some(aid()));
}

#[test]
fn a_resolver_may_refuse_a_malformed_keyid_or_a_key_state_itself() {
    for refused in [Kind::MalformedKey, Kind::UnsupportedSigner] {
        let resolver: Resolver = Arc::new(move |keyid: &str| {
            Err(Error::detailed(
                refused,
                format!("{keyid} is refused."),
                keyid,
            ))
        });
        let sent = signed(SignOptions {
            keyid: Some("not-an-aid".into()),
            ..Default::default()
        });
        let err = sent.verify(resolving(resolver)).unwrap_err();
        assert_eq!(err.kind, refused);
        assert_eq!(err.detail.as_deref(), Some("not-an-aid"));
    }
}

#[test]
fn a_d_prefixed_keyid_is_never_decoded_as_a_key_when_a_resolver_is_supplied() {
    // Profile R1: D... embeds the inception key, so decoding it would undo pre-rotation. The
    // request is signed by the key the prefix embeds; the resolver says the current key is another.
    let inception = cesr('D', &raw(&key()));
    let current = || resolving(table(&[(&inception, raw(&other()))]));
    let by_inception = signed(SignOptions {
        keyid: Some(inception.clone()),
        ..Default::default()
    });
    assert_eq!(by_inception.kind(current()), Kind::SignatureMismatch);
    let by_current = sign_as(
        &other(),
        "POST",
        URL,
        &[],
        with_body(SignOptions {
            keyid: Some(inception.clone()),
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(by_current.verify(current()).unwrap().aid, inception);
}

#[test]
fn a_resolver_with_no_keyid_to_resolve_is_a_missing_key() {
    let sent = signed(under_aid()).mangle(&format!(";keyid=\"{}\"", aid()), "");
    assert_eq!(
        sent.kind(resolving(table(&[(&aid(), raw(&key()))]))),
        Kind::MissingKey
    );
}

#[test]
fn an_empty_keyid_is_a_missing_key() {
    let sent = signed(SignOptions {
        keyid: Some(String::new()),
        ..Default::default()
    });
    assert_eq!(sent.kind(resolving(table(&[]))), Kind::MissingKey);
}

#[test]
fn expected_aid_and_a_resolver_together_are_a_caller_error() {
    let sent = signed(SignOptions::default());
    let opts = VerifyOptions {
        expected_aid: Some(key().aid()),
        ..resolving(table(&[]))
    };
    assert_eq!(sent.kind(opts), Kind::InvalidArgument);
}

#[test]
fn verify_options_debug_names_the_resolver_without_calling_it() {
    let shown = format!("{:?}", resolving(table(&[])));
    assert!(shown.contains("<resolver>"), "{shown}");
    assert!(format!("{:?}", VerifyOptions::default()).contains("resolve: None"));
}

// --- component identifiers with parameters ---

#[test]
fn req_names_a_request_component_from_a_response() {
    assert_eq!(req("@Method"), "\"@method\";req");
    assert_eq!(req("Content-Digest"), "\"content-digest\";req");
}

#[test]
fn a_caller_may_name_components_in_their_serialized_form() {
    let sent = signed(covering(&[
        "\"@method\"",
        "\"@PATH\"",
        "@query",
        "\"content-digest\"",
    ]));
    let verdict = sent.verify(VerifyOptions::default()).unwrap();
    assert_eq!(
        verdict.covered,
        ["@method", "@path", "@query", "content-digest"]
    );
}

#[test]
fn signing_a_duplicate_component_is_refused() {
    let err = sign_as(
        &key(),
        "POST",
        URL,
        &[],
        with_body(covering(&["@method", "@method", "content-digest"])),
    )
    .unwrap_err();
    assert_eq!(err.kind, Kind::DuplicateComponent);
    assert_eq!(err.detail.as_deref(), Some("@method"));
}

#[test]
fn a_malformed_component_spec_is_an_unsupported_component() {
    let err = sign_as(&key(), "POST", URL, &[], with_body(covering(&["\"@path"]))).unwrap_err();
    assert_eq!(err.kind, Kind::UnsupportedComponent);
    assert_eq!(err.detail.as_deref(), Some("\"@path"));
}

#[test]
fn a_signer_refuses_an_unsupported_component_parameter() {
    let opts = with_body(covering(&["\"@method\";sf", "@path", "content-digest"]));
    assert_eq!(
        kind_of(sign_as(&key(), "POST", URL, &[], opts)),
        Kind::UnsupportedComponent
    );
}

// --- responses (RFC 9421 section 2.4) ---

#[test]
fn a_signed_response_verifies_and_binds_its_request() {
    let verdict = check(&respond(SignOptions::default()), VerifyOptions::default()).unwrap();
    assert_eq!(verdict.aid, key().aid());
    assert_eq!(
        verdict.covered,
        [
            "@status",
            "\"@method\";req",
            "\"@path\";req",
            "\"@query\";req",
            "content-digest",
            "\"content-digest\";req"
        ]
    );
}

fn response_base(status: u16, asked: Option<&Request>, covered: &[&str]) -> fiki::Result<String> {
    let params = SignatureParams {
        created: Some(AT),
        keyid: Some("k".into()),
        ..Default::default()
    };
    response_signature_base(status, &BTreeMap::new(), asked, &strings(covered), &params)
        .map(|base| String::from_utf8(base).unwrap())
}

#[test]
fn the_status_line_is_three_digits_inclusive() {
    for status in [100, 204, 999] {
        let base = response_base(status, None, &["@status"]).unwrap();
        assert_eq!(
            base.lines().next().unwrap(),
            format!("\"@status\": {status}")
        );
    }
}

#[test]
fn a_status_that_is_not_three_digits_has_no_status_line() {
    let signed_200 = respond(SignOptions::default());
    for status in [99, 1000] {
        let err = response_base(status, None, &["@status"]).unwrap_err();
        assert_eq!(err.kind, Kind::MissingComponent);
        assert_eq!(err.detail.as_deref(), Some("@status"));
        let err = check_as(
            status,
            &signed_200,
            Some(&request()),
            Some(RESPONSE_BODY),
            VerifyOptions::default(),
        );
        assert_eq!(kind_of(err), Kind::MissingComponent);
    }
}

#[test]
fn the_req_lines_carry_the_request_values() {
    let covered = [
        "@status",
        "\"@method\";req",
        "\"@path\";req",
        "\"@query\";req",
        "\"content-digest\";req",
    ];
    let base = response_base(200, Some(&request()), &covered).unwrap();
    let lines: Vec<&str> = base.lines().collect();
    assert_eq!(
        lines[1..5],
        [
            "\"@method\";req: POST".to_string(),
            "\"@path\";req: /identifiers".to_string(),
            "\"@query\";req: ?type=rot".to_string(),
            format!("\"content-digest\";req: {}", content_digest(BODY)),
        ]
    );
}

#[test]
fn an_altered_status_is_refused() {
    let headers = respond(SignOptions::default());
    let err = check_as(
        201,
        &headers,
        Some(&request()),
        Some(RESPONSE_BODY),
        VerifyOptions::default(),
    );
    assert_eq!(kind_of(err), Kind::SignatureMismatch);
}

#[test]
fn a_swapped_response_body_is_refused() {
    let headers = respond(SignOptions::default());
    let err = check_as(
        200,
        &headers,
        Some(&request()),
        Some(br#"{"done": false}"#),
        VerifyOptions::default(),
    );
    assert_eq!(kind_of(err), Kind::DigestMismatch);
}

#[test]
fn a_response_checked_against_a_different_request_is_refused() {
    let elsewhere = Request {
        url: "https://keria.example.com/other?type=rot".into(),
        ..request()
    };
    let err = check_as(
        200,
        &respond(SignOptions::default()),
        Some(&elsewhere),
        Some(RESPONSE_BODY),
        VerifyOptions::default(),
    );
    assert_eq!(kind_of(err), Kind::SignatureMismatch);
}

#[test]
fn a_response_with_no_request_covers_only_its_own_components() {
    let opts = SignOptions {
        body: Some(RESPONSE_BODY.to_vec()),
        ..Default::default()
    };
    let headers = respond_to(None, &[], opts).unwrap();
    let verdict = check_as(
        200,
        &headers,
        None,
        Some(RESPONSE_BODY),
        VerifyOptions::default(),
    )
    .unwrap();
    assert_eq!(verdict.covered, ["@status", "content-digest"]);
}

#[test]
fn a_bodyless_response_to_a_bodyless_request_covers_no_digest() {
    let get = Request {
        method: "GET".into(),
        url: URL.into(),
        ..Default::default()
    };
    let headers = respond_to(Some(&get), &[], SignOptions::default()).unwrap();
    let verdict = check_as(200, &headers, Some(&get), None, VerifyOptions::default()).unwrap();
    assert_eq!(
        verdict.covered,
        [
            "@status",
            "\"@method\";req",
            "\"@path\";req",
            "\"@query\";req"
        ]
    );
}

#[test]
fn signing_a_response_body_without_its_digest_is_refused() {
    let err = respond_to(
        Some(&request()),
        &[],
        SignOptions {
            body: Some(RESPONSE_BODY.to_vec()),
            ..covering(&["@status"])
        },
    );
    assert_eq!(kind_of(err), Kind::UncoveredBody);
}

#[test]
fn a_req_component_with_no_request_to_read_it_from_is_missing() {
    let opts = SignOptions {
        body: Some(RESPONSE_BODY.to_vec()),
        ..covering(&["@status", &req("@path"), "content-digest"])
    };
    assert_eq!(kind_of(respond_to(None, &[], opts)), Kind::MissingComponent);
    let headers = respond(SignOptions::default());
    let err = check_as(
        200,
        &headers,
        None,
        Some(RESPONSE_BODY),
        VerifyOptions::default(),
    );
    assert_eq!(kind_of(err), Kind::MissingComponent);
}

#[test]
fn a_req_field_the_request_lacks_is_missing() {
    let bare = Request {
        method: "POST".into(),
        url: URL.into(),
        ..Default::default()
    };
    let opts = SignOptions {
        body: Some(RESPONSE_BODY.to_vec()),
        ..covering(&["@status", &req("content-digest"), "content-digest"])
    };
    assert_eq!(
        kind_of(respond_to(Some(&bare), &[], opts)),
        Kind::MissingComponent
    );
}

#[test]
fn a_signed_401_is_verified_like_any_other_response() {
    let opts = SignOptions {
        body: Some(RESPONSE_BODY.to_vec()),
        created: Some(AT),
        ..Default::default()
    };
    let headers = sign_response(&key(), 401, Some(&request()), &BTreeMap::new(), &opts).unwrap();
    let verdict = check_as(
        401,
        &headers,
        Some(&request()),
        Some(RESPONSE_BODY),
        VerifyOptions::default(),
    );
    assert_eq!(verdict.unwrap().aid, key().aid());
}

#[test]
fn an_unsigned_401_is_unauthenticated_before_anything_else() {
    let unsigned = headers(&[("Content-Type", "application/json")]);
    let err = check_as(
        401,
        &unsigned,
        Some(&request()),
        Some(br#"{"title": "no"}"#),
        VerifyOptions::default(),
    );
    assert_eq!(kind_of(err), Kind::Unauthenticated);
}

#[test]
fn an_unsigned_200_is_missing_its_signature() {
    let err = check_as(
        200,
        &BTreeMap::new(),
        Some(&request()),
        None,
        VerifyOptions::default(),
    );
    assert_eq!(kind_of(err), Kind::MissingSignature);
}

#[test]
fn served_authorities_are_a_caller_error_on_a_response() {
    let opts = VerifyOptions {
        authorities: Some(BTreeSet::from(["keria.example.com".to_string()])),
        ..Default::default()
    };
    assert_eq!(
        kind_of(check(&respond(SignOptions::default()), opts)),
        Kind::InvalidArgument
    );
}

// --- the covered list, as received ---

#[test]
fn an_unsupported_component_in_a_request_is_refused_not_dropped() {
    for covered in [
        "\"@method\";sf",
        "\"@method\";req",
        "\"@status\"",
        "\"@target-uri\"",
    ] {
        let sent = signed(SignOptions::default()).mangle("\"@method\"", covered);
        assert_eq!(
            sent.kind(VerifyOptions::default()),
            Kind::UnsupportedComponent,
            "{covered}"
        );
    }
}

#[test]
fn an_unsupported_component_in_a_response_is_refused() {
    for (old, new) in [
        ("\"@status\"", "\"@status\";req"),
        ("\"@path\";req", "\"@path\""),
        ("\"@path\";req", "\"@path\";req=?0"),
        ("\"@path\";req", "\"@path\";req;bs"),
    ] {
        let headers = mangled(respond(SignOptions::default()), old, new);
        assert_eq!(
            kind_of(check(&headers, VerifyOptions::default())),
            Kind::UnsupportedComponent,
            "{new}"
        );
    }
}

#[test]
fn a_duplicate_component_is_refused() {
    let sent = signed(SignOptions::default()).mangle("\"@path\"", "\"@path\" \"@path\"");
    assert_eq!(
        sent.kind(VerifyOptions::default()),
        Kind::DuplicateComponent
    );
}

#[test]
fn a_duplicate_is_found_whatever_the_parameter_order_and_before_it_is_unsupported() {
    let headers = mangled(
        respond(SignOptions::default()),
        "\"content-digest\";req",
        "\"content-digest\";req;sf \"content-digest\";sf;req",
    );
    assert_eq!(
        kind_of(check(&headers, VerifyOptions::default())),
        Kind::DuplicateComponent
    );
}

// --- Signature-Input, as received ---

#[test]
fn a_malformed_signature_input_member_is_refused() {
    let created = format!(";created={AT}");
    for (old, new) in [
        ("\"content-digest\"", "\"Content-Digest\"".to_string()),
        (created.as_str(), format!(";created={AT};context=\"x\"")),
        (created.as_str(), ";created=\"soon\"".to_string()),
        (created.as_str(), ";created=?1".to_string()),
        (created.as_str(), ";created=1.5".to_string()),
        ("alg=\"ed25519\"", "alg=ed25519".to_string()),
        ("\"@path\"", "path".to_string()),
    ] {
        let sent = signed(SignOptions::default()).mangle(old, &new);
        assert_eq!(
            sent.kind(VerifyOptions::default()),
            Kind::MalformedSignatureInput,
            "{new}"
        );
    }
}

#[test]
fn a_signature_input_member_that_is_not_an_inner_list_is_refused() {
    let mut sent = signed(SignOptions::default());
    sent.headers
        .insert("Signature-Input".into(), "sig=\"not a list\"".into());
    assert_eq!(
        sent.kind(VerifyOptions::default()),
        Kind::MalformedSignatureInput
    );
}

#[test]
fn two_labels_in_the_signature_header_are_malformed() {
    let mut sent = signed(SignOptions::default());
    let value = sent.headers["Signature"]
        .split_once('=')
        .unwrap()
        .1
        .to_string();
    let both = format!("{}, other={value}", sent.headers["Signature"]);
    sent.headers.insert("Signature".into(), both);
    assert_eq!(
        sent.kind(VerifyOptions::default()),
        Kind::MalformedSignatureLabel
    );
}

#[test]
fn a_signature_that_is_not_64_bytes_is_a_malformed_value() {
    let mut sent = signed(SignOptions::default());
    sent.headers.insert(
        "Signature".into(),
        format!("sig=:{}:", encode(&[0u8; 32], B64STD, true)),
    );
    assert_eq!(
        sent.kind(VerifyOptions::default()),
        Kind::MalformedSignatureValue
    );
}

#[test]
fn a_signature_member_that_is_not_a_byte_sequence_is_found_before_the_labels() {
    for member in ["sig=\"not bytes\"", "sig=token", "sig=(:AAAA:)"] {
        let mut sent = signed(SignOptions::default());
        let value = sent.headers["Signature-Input"]
            .split_once('=')
            .unwrap()
            .1
            .to_string();
        let both = format!("{}, other={value}", sent.headers["Signature-Input"]);
        sent.headers.insert("Signature-Input".into(), both);
        sent.headers.insert("Signature".into(), member.into());
        assert_eq!(
            sent.kind(VerifyOptions::default()),
            Kind::MalformedSignatureValue,
            "{member}"
        );
    }
}

// --- the section 9 order ---

#[test]
fn an_unsigned_message_is_missing_its_signature_first() {
    let mut sent = signed(SignOptions::default());
    sent.headers.remove("Signature");
    sent.headers.remove("Signature-Input");
    assert_eq!(sent.kind(VerifyOptions::default()), Kind::MissingSignature);
}

#[test]
fn an_unparsable_signature_is_reported_before_an_unparsable_input() {
    let mut sent = signed(SignOptions::default());
    sent.headers.insert("Signature".into(), "((((".into());
    sent.headers.insert("Signature-Input".into(), "((((".into());
    assert_eq!(
        sent.kind(VerifyOptions::default()),
        Kind::MalformedSignature
    );
}

#[test]
fn a_malformed_key_is_reported_before_an_unsupported_algorithm() {
    let sent = signed(SignOptions::default());
    let keyid = sent.keyid();
    let sent = sent
        .mangle(&keyid, "not-a-key")
        .mangle("alg=\"ed25519\"", "alg=\"rsa-pss-sha512\"");
    assert_eq!(sent.kind(VerifyOptions::default()), Kind::MalformedKey);
}

#[test]
fn staleness_is_reported_before_expiry() {
    let sent = signed(SignOptions {
        expires: Some(AT + 10),
        ..Default::default()
    });
    let opts = VerifyOptions {
        max_age: Some(300),
        skew: Some(60),
        now: Some(AT + 1000),
        ..Default::default()
    };
    assert_eq!(sent.kind(opts), Kind::SignatureTooOld);
}

// --- the minimum covered set (profile section 3) ---

#[test]
fn the_minimum_sets_are_the_profiles() {
    assert_eq!(REQUEST_MINIMUM, ["@method", "@path", "@query"]);
    assert_eq!(
        RESPONSE_MINIMUM.to_vec(),
        [
            "@status".to_string(),
            req("@method"),
            req("@path"),
            req("@query")
        ]
    );
}

#[test]
fn a_request_covering_the_minimum_verifies() {
    let sent = signed(SignOptions::default());
    assert_eq!(
        sent.verify(minimum(&REQUEST_MINIMUM)).unwrap().aid,
        key().aid()
    );
    // Named in serialized form, and beyond the profile's own.
    assert!(sent
        .verify(minimum(&["\"@method\"", "\"@PATH\"", "\"@query\""]))
        .is_ok());
    assert!(sent
        .verify(minimum(&["@method", "@path", "@query", "@authority"]))
        .is_ok());
}

#[test]
fn a_request_covering_less_than_the_minimum_is_refused_even_though_it_verifies() {
    let sent = signed(covering(&["@method", "@path", "content-digest"]));
    assert!(sent.verify(VerifyOptions::default()).is_ok());
    let err = sent.verify(minimum(&REQUEST_MINIMUM)).unwrap_err();
    assert_eq!(err.kind, Kind::InsufficientCoverage);
    assert_eq!(err.detail.as_deref(), Some("@query"));
}

#[test]
fn a_minimum_may_add_requirements_beyond_the_profiles() {
    let sent = signed(covering(&["@method", "@path", "@query", "content-digest"]));
    let err = sent
        .verify(minimum(&["@method", "@path", "@query", "@authority"]))
        .unwrap_err();
    assert_eq!(err.detail.as_deref(), Some("@authority"));
}

#[test]
fn a_body_without_a_covered_digest_is_insufficient_coverage() {
    for (extra, body) in [
        (vec![("Content-Length", "18")], None),
        (vec![("Content-Length", "many")], None),
        (vec![("Content-Length", "")], None),
        (vec![("Content-Length", "-5")], None),
        (vec![("Content-Length", "+3")], None),
        (vec![("Content-Length", "18 bytes")], None),
        (vec![("Transfer-Encoding", "chunked")], None),
        (vec![], Some(BODY.to_vec())),
    ] {
        let mut sent = bodiless(&extra, SignOptions::default());
        sent.body = body;
        let err = sent.verify(minimum(&REQUEST_MINIMUM)).unwrap_err();
        assert_eq!(err.kind, Kind::InsufficientCoverage, "{extra:?}");
        assert_eq!(err.detail.as_deref(), Some("content-digest"));
    }
}

#[test]
fn a_bodyless_request_needs_no_digest_under_a_minimum() {
    let get = sign_as(&key(), "GET", URL, &[], SignOptions::default()).unwrap();
    assert!(get.verify(minimum(&REQUEST_MINIMUM)).is_ok());
    for length in ["0", "000", " 0 "] {
        let mut sent = bodiless(&[("Content-Length", length)], SignOptions::default());
        sent.body = Some(Vec::new());
        assert!(sent.verify(minimum(&REQUEST_MINIMUM)).is_ok(), "{length:?}");
    }
}

#[test]
fn insufficient_coverage_is_reported_before_the_key() {
    let sent = signed(covering(&["@method", "@path", "content-digest"]));
    let keyid = sent.keyid();
    let sent = sent.mangle(&keyid, "not-a-key");
    assert_eq!(
        sent.kind(minimum(&REQUEST_MINIMUM)),
        Kind::InsufficientCoverage
    );
}

#[test]
fn a_response_covering_the_minimum_verifies() {
    assert!(check(&respond(SignOptions::default()), minimum(&RESPONSE_MINIMUM)).is_ok());
}

#[test]
fn a_response_missing_a_req_component_is_refused() {
    let headers = respond(covering(&[
        "@status",
        &req("@method"),
        &req("@query"),
        "content-digest",
        &req("content-digest"),
    ]));
    let err = check(&headers, minimum(&RESPONSE_MINIMUM)).unwrap_err();
    assert_eq!(err.kind, Kind::InsufficientCoverage);
    assert_eq!(err.detail, Some(req("@path")));
}

#[test]
fn a_response_body_without_its_digest_is_refused() {
    let headers = respond_to(
        Some(&request()),
        &[("Content-Length", "14")],
        SignOptions::default(),
    )
    .unwrap();
    let err = check(&headers, minimum(&RESPONSE_MINIMUM)).unwrap_err();
    assert_eq!(err.kind, Kind::InsufficientCoverage);
    assert_eq!(err.detail.as_deref(), Some("content-digest"));
}

#[test]
fn a_response_to_a_request_with_a_body_must_cover_the_requests_digest() {
    let mut covered: Vec<&str> = RESPONSE_MINIMUM.to_vec();
    covered.push("content-digest");
    let err = check(&respond(covering(&covered)), minimum(&RESPONSE_MINIMUM)).unwrap_err();
    assert_eq!(err.kind, Kind::InsufficientCoverage);
    assert_eq!(err.detail, Some(req("content-digest")));
}

#[test]
fn a_response_judges_its_requests_body_by_content_not_headers() {
    // Profile section 3: both sides hold the whole request by the time a response is signed or
    // verified, so the request's headers do not count (@7p9s3g9k).
    for announced in [("Transfer-Encoding", "chunked"), ("Content-Length", "18")] {
        let digest = content_digest(BODY);
        let asked = Request {
            method: "POST".into(),
            url: URL.into(),
            headers: headers(&[announced, ("Content-Digest", &digest)]),
            body: None,
        };
        let opts = SignOptions {
            body: Some(RESPONSE_BODY.to_vec()),
            ..Default::default()
        };
        let signed = respond_to(Some(&asked), &[], opts).unwrap();
        let verdict = check_as(
            200,
            &signed,
            Some(&asked),
            Some(RESPONSE_BODY),
            minimum(&RESPONSE_MINIMUM),
        )
        .unwrap();
        assert!(!verdict.covered.contains(&req("content-digest")));
    }
}

#[test]
fn a_default_response_to_a_body_with_no_digest_to_bind_is_refused_at_signing() {
    let asked = Request {
        method: "POST".into(),
        url: URL.into(),
        headers: BTreeMap::new(),
        body: Some(BODY.to_vec()),
    };
    assert_eq!(
        kind_of(respond_to(Some(&asked), &[], SignOptions::default())),
        Kind::UncoveredBody
    );
}

#[test]
fn a_head_response_carrying_a_content_length_has_no_body() {
    let head = Request {
        method: "HEAD".into(),
        url: URL.into(),
        ..Default::default()
    };
    let headers = respond_to(
        Some(&head),
        &[("Content-Length", "898")],
        SignOptions::default(),
    )
    .unwrap();
    let verdict = check_as(200, &headers, Some(&head), None, minimum(&RESPONSE_MINIMUM)).unwrap();
    assert!(!verdict.covered.contains(&"content-digest".to_string()));
}

// --- the first review's findings and the profile's draft 6 (@2f227n4r) ---

#[test]
fn a_missing_keyid_is_reported_before_the_covered_list_and_the_labels() {
    let resolve = || table(&[(&aid(), raw(&key()))]);
    let sent = signed(SignOptions {
        keyid: Some(aid()),
        ..covering(&["@method", "content-digest"])
    })
    .mangle(&format!(";keyid=\"{}\"", aid()), "");
    let opts = VerifyOptions {
        minimum: Some(strings(&REQUEST_MINIMUM)),
        ..resolving(resolve())
    };
    assert_eq!(sent.kind(opts), Kind::MissingKey);

    let mut sent = signed(under_aid()).mangle(&format!(";keyid=\"{}\"", aid()), "");
    let value = sent.headers["Signature-Input"]
        .split_once('=')
        .unwrap()
        .1
        .to_string();
    let both = format!("{}, other={value}", sent.headers["Signature-Input"]);
    sent.headers.insert("Signature-Input".into(), both);
    assert_eq!(sent.kind(resolving(resolve())), Kind::MissingKey);
}

#[test]
fn a_missing_keyid_is_fine_when_the_verifier_names_the_key() {
    let sent = signed(SignOptions::default());
    let keyid = sent.keyid();
    let sent = sent.mangle(&format!(";keyid=\"{keyid}\""), "");
    let opts = VerifyOptions {
        expected_aid: Some(key().aid()),
        ..Default::default()
    };
    // Verifies against the key, then mismatches only because the keyid was part of what was signed.
    let err = sent.verify(opts).unwrap_err();
    assert_eq!(err.kind, Kind::SignatureMismatch);
}

#[test]
fn an_expected_aid_reports_the_keyid_as_received() {
    let opts = VerifyOptions {
        expected_aid: Some(key().aid()),
        ..Default::default()
    };
    let verdict = signed(SignOptions::default()).verify(opts).unwrap();
    assert_eq!(verdict.keyid, Some(encode(&raw(&key()), B64URL, false)));
}

#[test]
fn a_signer_given_a_minimum_refuses_a_covered_list_below_it() {
    let below = SignOptions {
        minimum: Some(strings(&REQUEST_MINIMUM)),
        ..covering(&["@method", "@path"])
    };
    assert_eq!(
        kind_of(sign_as(&key(), "POST", URL, &[], below)),
        Kind::InsufficientCoverage
    );
    let sent = signed(SignOptions {
        minimum: Some(strings(&REQUEST_MINIMUM)),
        ..Default::default()
    });
    assert!(sent.verify(minimum(&REQUEST_MINIMUM)).is_ok());
}

#[test]
fn a_signer_given_a_minimum_refuses_a_body_it_would_not_cover() {
    let opts = SignOptions {
        minimum: Some(strings(&REQUEST_MINIMUM)),
        ..Default::default()
    };
    assert_eq!(
        kind_of(sign_as(
            &key(),
            "POST",
            URL,
            &[("Transfer-Encoding", "chunked")],
            opts
        )),
        Kind::InsufficientCoverage
    );
}

#[test]
fn a_response_signer_given_a_minimum_refuses_a_covered_list_below_it() {
    let below = SignOptions {
        body: Some(RESPONSE_BODY.to_vec()),
        minimum: Some(strings(&RESPONSE_MINIMUM)),
        ..covering(&["@status", "content-digest"])
    };
    assert_eq!(
        kind_of(respond_to(Some(&request()), &[], below)),
        Kind::InsufficientCoverage
    );
    let headers = respond(SignOptions {
        minimum: Some(strings(&RESPONSE_MINIMUM)),
        ..Default::default()
    });
    assert!(check(&headers, minimum(&RESPONSE_MINIMUM)).is_ok());
}

#[test]
fn a_response_from_an_aid_other_than_the_expected_one_is_an_unknown_key() {
    let headers = respond(under_aid());
    let expecting = |keyid: String| VerifyOptions {
        expected_keyid: Some(keyid),
        ..resolving(table(&[(&aid(), raw(&key()))]))
    };
    assert_eq!(
        check(&headers, expecting(aid())).unwrap().keyid,
        Some(aid())
    );
    let err = check(&headers, expecting(cesr('E', &[0u8; 32]))).unwrap_err();
    assert_eq!(err.kind, Kind::UnknownKey);
    assert_eq!(err.detail, Some(aid()));
    // A signature with no keyid at all is not from the expected one either.
    let unnamed = mangled(headers, &format!(";keyid=\"{}\"", aid()), "");
    let opts = VerifyOptions {
        expected_keyid: Some(aid()),
        expected_aid: Some(key().aid()),
        ..Default::default()
    };
    assert_eq!(kind_of(check(&unnamed, opts)), Kind::UnknownKey);
}

#[test]
fn a_covered_authority_outside_the_served_set_is_a_signature_mismatch() {
    let sent = sign_as(
        &key(),
        "POST",
        "/identifiers",
        &[("Host", "other.example.com")],
        with_body(SignOptions::default()),
    )
    .unwrap();
    let serving = |name: &str| VerifyOptions {
        authorities: Some(BTreeSet::from([name.to_string()])),
        ..Default::default()
    };
    assert!(sent.verify(serving("other.example.com")).is_ok());
    let err = sent.verify(serving("keria.example.com")).unwrap_err();
    assert_eq!(err.kind, Kind::SignatureMismatch);
    assert_eq!(err.detail.as_deref(), Some("other.example.com"));
    let uncovered = signed(covering(&["@method", "@path", "@query", "content-digest"]));
    assert!(uncovered.verify(serving("elsewhere.example.com")).is_ok());
}

#[test]
fn a_base_that_cannot_be_built_is_a_signature_mismatch() {
    for value in ["café", "two\nlines", "bell\u{7}"] {
        let mut sent = sign_as(
            &key(),
            "POST",
            URL,
            &[("X-Note", "plain")],
            with_body(covering(&[
                "@method",
                "@path",
                "@query",
                "x-note",
                "content-digest",
            ])),
        )
        .unwrap();
        sent.headers.insert("X-Note".into(), value.into());
        assert_eq!(
            sent.kind(VerifyOptions::default()),
            Kind::SignatureMismatch,
            "{value:?}"
        );
        let params = SignatureParams {
            created: Some(AT),
            keyid: Some("k".into()),
            ..Default::default()
        };
        let err = signature_base(
            "GET",
            URL,
            &headers(&[("X-Note", value)]),
            &strings(&["x-note"]),
            &params,
        )
        .unwrap_err();
        assert_eq!(err.kind, Kind::SignatureMismatch);
    }
}

#[test]
fn a_tab_in_a_field_value_still_builds() {
    let sent = sign_as(
        &key(),
        "POST",
        URL,
        &[("X-Note", "a\tb")],
        with_body(covering(&[
            "@method",
            "@path",
            "@query",
            "x-note",
            "content-digest",
        ])),
    )
    .unwrap();
    assert!(sent.verify(VerifyOptions::default()).is_ok());
}

// --- created is required under a minimum (@7p9s3g9k) ---

fn without_created() -> Sent {
    signed(SignOptions::default()).mangle(&format!(";created={AT}"), "")
}

#[test]
fn a_minimum_requires_created_as_part_of_signature_input() {
    assert_eq!(
        without_created().kind(minimum(&REQUEST_MINIMUM)),
        Kind::MalformedSignatureInput
    );
    let doubled = without_created().mangle("\"@path\"", "\"@path\" \"@path\"");
    assert_eq!(
        doubled.kind(minimum(&REQUEST_MINIMUM)),
        Kind::MalformedSignatureInput
    );
}

#[test]
fn without_a_minimum_created_stays_optional_as_rfc_9421_makes_it() {
    // The missing created surfaces only as the signature it breaks.
    assert_eq!(
        without_created().kind(VerifyOptions::default()),
        Kind::SignatureMismatch
    );
}

// --- a covered "content-digest";req is recomputed over the request body (bakobo/fiki#4) ---

fn swapped() -> Request {
    Request {
        body: Some(br#"{"hello": "mallory"}"#.to_vec()),
        ..request()
    }
}

fn unreadable(body: Option<&[u8]>) -> Request {
    Request {
        method: "POST".into(),
        url: URL.into(),
        headers: headers(&[("Content-Digest", "((((")]),
        body: body.map(<[u8]>::to_vec),
    }
}

fn binding_both() -> SignOptions {
    let mut covered: Vec<String> = RESPONSE_MINIMUM.iter().map(|s| s.to_string()).collect();
    covered.extend([req("content-digest"), "content-digest".into()]);
    SignOptions {
        body: Some(RESPONSE_BODY.to_vec()),
        covered: Some(covered),
        ..Default::default()
    }
}

#[test]
fn a_swapped_request_body_is_refused_when_the_response_binds_its_digest() {
    let err = check_as(
        200,
        &respond(SignOptions::default()),
        Some(&swapped()),
        Some(RESPONSE_BODY),
        VerifyOptions::default(),
    );
    assert_eq!(kind_of(err), Kind::DigestMismatch);
}

#[test]
fn an_unreadable_request_digest_is_malformed_when_the_response_binds_it() {
    let headers = respond_to(Some(&unreadable(None)), &[], binding_both()).unwrap();
    let err = check_as(
        200,
        &headers,
        Some(&unreadable(Some(BODY))),
        Some(RESPONSE_BODY),
        VerifyOptions::default(),
    );
    assert_eq!(kind_of(err), Kind::MalformedDigest);
}

#[test]
fn a_malformed_request_digest_outranks_a_mismatched_response_digest() {
    // Section 9 puts malformed-digest before digest-mismatch, so every covered digest is parsed
    // before any hash is compared.
    let headers = respond_to(Some(&unreadable(None)), &[], binding_both()).unwrap();
    let err = check_as(
        200,
        &headers,
        Some(&unreadable(Some(BODY))),
        Some(br#"{"done": false}"#),
        VerifyOptions::default(),
    );
    assert_eq!(kind_of(err), Kind::MalformedDigest);
}

#[test]
fn a_signer_will_not_bind_a_request_digest_its_body_contradicts() {
    assert_eq!(
        kind_of(respond_to(Some(&swapped()), &[], SignOptions::default())),
        Kind::DigestMismatch
    );
    assert_eq!(
        kind_of(respond_to(
            Some(&unreadable(Some(BODY))),
            &[],
            SignOptions::default()
        )),
        Kind::MalformedDigest
    );
    // b"" is a body that was supplied, and it contradicts this digest.
    let empty = Request {
        body: Some(Vec::new()),
        ..request()
    };
    assert_eq!(
        kind_of(respond_to(Some(&empty), &[], binding_both())),
        Kind::DigestMismatch
    );
}

#[test]
fn a_bound_request_digest_with_no_request_body_to_check_is_a_caller_error() {
    let bodiless = Request {
        body: None,
        ..request()
    };
    let err = check_as(
        200,
        &respond(SignOptions::default()),
        Some(&bodiless),
        Some(RESPONSE_BODY),
        VerifyOptions::default(),
    );
    assert_eq!(kind_of(err), Kind::InvalidArgument);
}

// --- a supplied minimum can only add to the profile's (bakobo/fiki#4) ---

#[test]
fn a_request_minimum_below_the_profiles_is_a_caller_error() {
    let sent = signed(SignOptions::default());
    for below in [vec![], vec!["@method", "@path"], vec!["\"@method\";req"]] {
        assert_eq!(
            sent.kind(minimum(&below)),
            Kind::InvalidArgument,
            "{below:?}"
        );
        let opts = SignOptions {
            minimum: Some(strings(&below)),
            ..Default::default()
        };
        assert_eq!(
            kind_of(sign_as(&key(), "POST", URL, &[], with_body(opts))),
            Kind::InvalidArgument
        );
    }
}

#[test]
fn a_response_minimum_below_the_profiles_is_a_caller_error() {
    let headers = respond(SignOptions::default());
    for below in [
        vec![],
        REQUEST_MINIMUM.to_vec(),
        vec!["@status", "\"@method\";req"],
    ] {
        assert_eq!(
            kind_of(check(&headers, minimum(&below))),
            Kind::InvalidArgument,
            "{below:?}"
        );
        let opts = SignOptions {
            minimum: Some(strings(&below)),
            ..Default::default()
        };
        assert_eq!(
            kind_of(respond_to(Some(&request()), &[], opts)),
            Kind::InvalidArgument
        );
    }
}

#[test]
fn a_malformed_spec_in_a_minimum_is_an_unsupported_component() {
    assert_eq!(
        signed(SignOptions::default()).kind(minimum(&["\"@method"])),
        Kind::UnsupportedComponent
    );
}

// --- an AID-shaped keyid is spelled canonically before any resolver sees it (bakobo/fiki#4) ---

#[test]
fn a_padding_bit_alias_is_malformed_even_through_a_resolver() {
    for code in ['B', 'D', 'E'] {
        let alias = padding_bit_alias(&cesr(code, &raw(&key())));
        let sent = signed(SignOptions {
            keyid: Some(alias.clone()),
            ..Default::default()
        });
        let always: Resolver = Arc::new(|_: &str| Ok(Some(raw(&key()))));
        let never: Resolver = Arc::new(|_: &str| Ok(None));
        assert_eq!(sent.kind(resolving(always)), Kind::MalformedKey, "{alias}");
        assert_eq!(sent.kind(resolving(never)), Kind::MalformedKey, "{alias}");
    }
}

#[test]
fn an_aid_shaped_keyid_outside_the_alphabet_is_malformed_through_a_resolver() {
    let sent = signed(SignOptions {
        keyid: Some(format!("E{}", "!".repeat(43))),
        ..Default::default()
    });
    let always: Resolver = Arc::new(|_: &str| Ok(Some(raw(&key()))));
    assert_eq!(sent.kind(resolving(always)), Kind::MalformedKey);
}

#[test]
fn a_keyid_of_another_shape_reaches_the_resolver_unchanged() {
    // Only B, D and E qb64 are checked for spelling; anything else is the resolver's to judge.
    let sent = signed(SignOptions {
        keyid: Some(format!("A{}", "!".repeat(43))),
        ..Default::default()
    });
    let seen: Resolver =
        Arc::new(|keyid: &str| Ok((keyid == format!("A{}", "!".repeat(43))).then(|| raw(&key()))));
    assert!(sent.verify(resolving(seen)).is_ok());
}

#[test]
fn a_canonical_aid_still_reaches_the_resolver() {
    let verdict = signed(under_aid()).verify(resolving(table(&[(&aid(), raw(&key()))])));
    assert_eq!(verdict.unwrap().aid, aid());
}

#[test]
fn a_raw_keyid_is_decoded_only_in_its_own_spelling() {
    let sent = signed(SignOptions::default());
    let keyid = sent.keyid();
    // The last character carries two bits a lenient decoder ignores; flip one of them.
    let last = B64URL
        .iter()
        .position(|a| *a == keyid.as_bytes()[42])
        .unwrap();
    let alias = format!("{}{}", &keyid[..42], B64URL[last ^ 1] as char);
    for bad in [
        alias.as_str(),
        &keyid[..42],
        &format!("{keyid}="),
        &format!("{}+", &keyid[..42]),
    ] {
        let mangled = signed(SignOptions::default()).mangle(&keyid, bad);
        assert_eq!(
            mangled.kind(VerifyOptions::default()),
            Kind::MalformedKey,
            "{bad}"
        );
    }
}

#[test]
fn a_malformed_spec_in_a_base_is_an_unsupported_component() {
    let params = SignatureParams::default();
    let spec = strings(&["\"@path"]);
    let err = signature_base("GET", URL, &BTreeMap::new(), &spec, &params).unwrap_err();
    assert_eq!(err.kind, Kind::UnsupportedComponent);
    let err = response_signature_base(200, &BTreeMap::new(), None, &spec, &params).unwrap_err();
    assert_eq!(err.kind, Kind::UnsupportedComponent);
}

#[test]
fn a_max_age_with_no_created_to_check_is_too_old_without_a_minimum() {
    // fiki always signs a created, so this message is assembled by hand from the public base.
    let params = SignatureParams {
        keyid: Some(key().keyid()),
        alg: Some("ed25519".into()),
        ..Default::default()
    };
    let covered = strings(&REQUEST_MINIMUM);
    let base = signature_base("GET", URL, &BTreeMap::new(), &covered, &params).unwrap();
    let text = String::from_utf8(base.clone()).unwrap();
    let input = text.rsplit_once("\"@signature-params\": ").unwrap().1;
    let sent = Sent {
        method: "GET".into(),
        url: URL.into(),
        body: None,
        headers: headers(&[
            ("Signature-Input", &format!("sig={input}")),
            (
                "Signature",
                &format!("sig=:{}:", encode(&key().sign(&base), B64STD, true)),
            ),
        ]),
    };
    assert!(sent.verify(VerifyOptions::default()).is_ok());
    let aged = VerifyOptions {
        max_age: Some(300),
        now: Some(AT),
        ..Default::default()
    };
    assert_eq!(sent.kind(aged), Kind::SignatureTooOld);
}

// --- small-order public keys are refused before any signature check (@2t8xctts, tick 27eo) ---

/// Encodings of small-order points: the identity, the identity spelled non-canonically (y = p + 1),
/// the point of order 2 (y = p - 1), and a point of order 4 (y = 0) under both signs.
fn small_order_keys() -> Vec<[u8; 32]> {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut non_canonical_identity = [0xffu8; 32];
    non_canonical_identity[0] = 0xee;
    non_canonical_identity[31] = 0x7f;
    let mut order_two = [0xffu8; 32];
    order_two[0] = 0xec;
    order_two[31] = 0x7f;
    let mut order_four_negative = [0u8; 32];
    order_four_negative[31] = 0x80;
    vec![
        identity,
        non_canonical_identity,
        order_two,
        [0u8; 32],
        order_four_negative,
    ]
}

/// The forgery tick 27eo reproduced in fiki-py: under the identity key, the signature 0x01
/// followed by 63 zero bytes verifies over any message with a lenient verifier.
fn forged_under(keyid: &str) -> Sent {
    let mut sent = signed(SignOptions {
        keyid: Some(keyid.to_string()),
        ..Default::default()
    });
    let mut forged = [0u8; 64];
    forged[0] = 1;
    sent.headers.insert(
        "Signature".into(),
        format!("sig=:{}:", encode(&forged, B64STD, true)),
    );
    sent
}

#[test]
fn a_small_order_key_is_malformed_through_an_inline_keyid() {
    for small in small_order_keys() {
        let sent = forged_under(&encode(&small, B64URL, false));
        let err = sent.verify(VerifyOptions::default()).unwrap_err();
        assert_eq!(err.kind, Kind::MalformedKey, "{small:02x?}");
    }
}

#[test]
fn a_small_order_key_is_malformed_through_a_resolver() {
    for small in small_order_keys() {
        let sent = forged_under(&aid());
        let resolver: Resolver = Arc::new(move |_: &str| Ok(Some(small)));
        let err = sent.verify(resolving(resolver)).unwrap_err();
        assert_eq!(err.kind, Kind::MalformedKey, "{small:02x?}");
        assert_eq!(err.detail, Some(aid()));
    }
}

#[test]
fn a_small_order_key_is_malformed_as_an_aid() {
    for small in small_order_keys() {
        let aid = fiki::to_aid(&small);
        assert_eq!(
            verifying_key(&aid).unwrap_err().kind,
            Kind::MalformedKey,
            "{aid}"
        );
        let opts = VerifyOptions {
            expected_aid: Some(aid.clone()),
            ..Default::default()
        };
        assert_eq!(
            forged_under("anything").kind(opts),
            Kind::MalformedKey,
            "{aid}"
        );
    }
}

#[test]
fn the_small_order_refusal_comes_before_the_algorithm() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let sent = forged_under(&encode(&identity, B64URL, false))
        .mangle("alg=\"ed25519\"", "alg=\"rsa-pss-sha512\"");
    assert_eq!(sent.kind(VerifyOptions::default()), Kind::MalformedKey);
}

// --- a field value is checked raw, and a method is never empty (@56qu7gyw) ---

fn noting(value: &str) -> Sent {
    let mut sent = sign_as(
        &key(),
        "POST",
        URL,
        &[("X-Note", "admin")],
        with_body(covering(&[
            "@method",
            "@path",
            "@query",
            "x-note",
            "content-digest",
        ])),
    )
    .unwrap();
    sent.headers.insert("X-Note".into(), value.into());
    sent
}

#[test]
fn a_line_break_or_nul_in_a_covered_value_is_refused_before_any_trimming() {
    for value in ["admin\r\n", "admin\n", "\r\nadmin", "admin\0", "admin\r"] {
        assert_eq!(
            noting(value).kind(VerifyOptions::default()),
            Kind::SignatureMismatch,
            "{value:?}"
        );
        let err = sign_as(
            &key(),
            "POST",
            URL,
            &[("X-Note", value)],
            with_body(covering(&["@method", "x-note", "content-digest"])),
        )
        .unwrap_err();
        assert_eq!(err.kind, Kind::SignatureMismatch, "{value:?}");
    }
}

#[test]
fn only_spaces_and_tabs_around_a_value_are_trimmed() {
    assert!(noting(" \tadmin\t ")
        .verify(VerifyOptions::default())
        .is_ok());
}

#[test]
fn an_empty_method_is_a_caller_error_wherever_at_method_is_built() {
    let err = sign_as(&key(), "", URL, &[], with_body(SignOptions::default())).unwrap_err();
    assert_eq!(err.kind, Kind::InvalidArgument);
    let sent = signed(SignOptions::default());
    let err = verify_request("", URL, &sent.headers, &VerifyOptions::default()).unwrap_err();
    assert_eq!(err.kind, Kind::InvalidArgument);
    let params = SignatureParams::default();
    let err = signature_base("", URL, &BTreeMap::new(), &strings(&["@method"]), &params);
    assert_eq!(kind_of(err), Kind::InvalidArgument);
    assert!(signature_base("", URL, &BTreeMap::new(), &strings(&["@path"]), &params).is_ok());
    let methodless = Request {
        method: String::new(),
        url: URL.into(),
        ..Default::default()
    };
    let err = response_base(200, Some(&methodless), &["@status", "\"@method\";req"]);
    assert_eq!(kind_of(err), Kind::InvalidArgument);
}

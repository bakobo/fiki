//! The ground the shared vectors do not cover: signing a fresh request, generating a key, the
//! parser's own refusal branches, and the freshness rules beyond the three cases refusals.json
//! pins. Those are not cross-implementation contracts — they are this port working.

use std::collections::BTreeMap;

use fiki::{
    content_digest, sign_request, signature_base, verify_request, verify_response, verifying_key,
    Authorities, ExpectedKeyid, Key, Kind, MaxAge, Minimum, SignOptions, SignatureParams,
    VerifyOptions,
};

/// The policy fiki 0.8 applied when a caller stated none: no minimum, no authority check and no
/// expected keyid. Format 3 makes a minimum the default for requests and responses alike, and
/// authorities and a response's expected keyid required decisions (`this.i` @524c8qgv), so a test
/// whose subject is something else states that policy rather than relying on it.
fn opted_out() -> VerifyOptions {
    VerifyOptions {
        minimum: Minimum::Off,
        authorities: Authorities::Unchecked,
        expected_keyid: ExpectedKeyid::Unchecked,
        ..Default::default()
    }
}

const SEED_AID: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
const URL_QUERY: &str = "https://api.example.com/things?limit=1&sort=name";
const SIGNED_AT: i64 = 1_700_000_000;
const BODY: &[u8] = br#"{"hello": "world"}"#;

fn key() -> Key {
    let seed: Vec<u8> = (0u8..32).collect();
    Key::from_seed(&seed).unwrap()
}

fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn params() -> SignatureParams {
    SignatureParams {
        created: Some(SIGNED_AT),
        keyid: Some("k".into()),
        ..Default::default()
    }
}

fn line(component: &str, method: &str, url: &str, hdrs: &[(&str, &str)]) -> String {
    let base = signature_base(
        method,
        url,
        &headers(hdrs),
        &[component.to_string()],
        &params(),
    )
    .unwrap();
    String::from_utf8(base)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string()
}

fn signed(opts: SignOptions) -> (Key, BTreeMap<String, String>) {
    let k = key();
    let opts = SignOptions {
        created: opts.created.or(Some(SIGNED_AT)),
        ..opts
    };
    let out = sign_request(&k, "POST", URL_QUERY, &BTreeMap::new(), &opts).unwrap();
    (k, out)
}

#[test]
fn keys_and_the_lens() {
    assert_eq!(
        key().aid(),
        SEED_AID,
        "the AID keripy derives for this seed"
    );
    assert_eq!(key().seed().len(), 32);
    assert_ne!(Key::generate().aid(), key().aid());
    assert_eq!(
        Key::from_seed(&[0u8; 31]).unwrap_err().kind,
        Kind::MalformedKey
    );
    let raw = verifying_key(SEED_AID).unwrap();
    assert_eq!(fiki::to_aid(raw.as_bytes()).unwrap(), SEED_AID);
}

#[test]
fn malformed_aids_are_refused() {
    for aid in [
        "B",                             // too short
        &format!("B{}", "A".repeat(44)), // too long
        &format!("D{}", "A".repeat(43)), // transferable prefix
        &format!("B{}", "!".repeat(43)), // outside the alphabet
        // "=" is inside base64's alphabet, so a lenient decoder would take this and decode short.
        &format!("B{}==", "A".repeat(41)),
        // SEED_AID with a bit set in the pad byte the code character replaces: the same 32 key
        // bytes under a second spelling, which would give one key two identifiers.
        "BQOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4",
    ] {
        assert_eq!(
            verifying_key(aid).unwrap_err().kind,
            Kind::MalformedKey,
            "{aid}"
        );
    }
}

#[test]
fn bytes_that_are_not_a_usable_key_are_refused_up_front() {
    // All-0xFF is a y at or above the field prime with the sign bit set: ed25519-dalek 2.x
    // decompresses it by reducing y, so it used to surface only as a failed signature. A key that
    // cannot be a key is refused as malformed before any signature is checked (`this.i` @34qlc8r3);
    // profile.rs pins every class of it on every path.
    let aid = fiki::to_aid(&[0xFFu8; 32]).unwrap();
    assert_eq!(verifying_key(&aid).unwrap_err().kind, Kind::MalformedKey);
}

#[test]
fn derived_components() {
    assert_eq!(
        line(
            "@authority",
            "GET",
            "/things",
            &[("Host", "API.example.com")]
        ),
        r#""@authority": api.example.com"#
    );
    assert_eq!(
        line("@authority", "GET", "https://EXAMPLE.com:443/f", &[]),
        r#""@authority": example.com"#
    );
    assert_eq!(
        line("@authority", "GET", "https://example.com:8443/f", &[]),
        r#""@authority": example.com:8443"#
    );
    assert_eq!(
        line("@path", "GET", "https://example.com", &[]),
        r#""@path": /"#
    );
    assert_eq!(
        line("@query", "GET", "https://example.com/f", &[]),
        r#""@query": ?"#
    );
    assert_eq!(
        line("@query", "GET", "https://example.com/p?baz=bat%2Dman", &[]),
        r#""@query": ?baz=bat%2Dman"#
    );
    // The method as sent, with no case transformation (`this.i` @22g0xkr8, RFC 9421 section
    // 2.2.1): "post" and "POST" are different methods.
    assert_eq!(
        line("@method", "post", "https://example.com/f", &[]),
        r#""@method": post"#
    );
    assert_eq!(
        line(
            "Content-Type",
            "GET",
            "https://x.example/f",
            &[("Content-Type", "  application/json  ")]
        ),
        r#""content-type": application/json"#
    );
    // A request target has no fragment, so a URL carrying one is refused rather than stripped
    // (`this.i`, "Host is validated like any authority, ... a fragment is refused"): a caller error
    // when signing. Format 3 changed this expectation; it used to be stripped.
    assert_eq!(
        signature_base(
            "GET",
            "https://example.com/f#frag",
            &BTreeMap::new(),
            &["@path".to_string()],
            &params()
        )
        .unwrap_err()
        .kind,
        Kind::InvalidArgument
    );
    // A host with a non-numeric suffix after the colon is not a port.
    assert_eq!(
        line("@authority", "GET", "https://[::1]/f", &[]),
        r#""@authority": [::1]"#
    );
    // An IPv6 literal keeps its brackets with a port too (RFC 3986 section 3.2.2), and a default
    // port is still dropped (`this.i` @4pz4mcgq).
    assert_eq!(
        line("@authority", "GET", "https://[::1]:8443/f", &[]),
        r#""@authority": [::1]:8443"#
    );
    assert_eq!(
        line("@authority", "GET", "https://[::1]:443/f", &[]),
        r#""@authority": [::1]"#
    );
    // The path and query as sent: no dot segments removed, nothing decoded or re-encoded.
    assert_eq!(
        line("@path", "GET", "https://x.example/a/../b/./%7Ec:d", &[]),
        r#""@path": /a/../b/./%7Ec:d"#
    );
    assert_eq!(
        // A literal space was here until format 3, which refuses one anywhere in a target.
        line("@query", "GET", "https://x.example/f?a=%2f&b=%20c", &[]),
        r#""@query": ?a=%2f&b=%20c"#
    );
}

#[test]
fn unbuildable_and_missing_components_are_refused() {
    let err = signature_base(
        "GET",
        "https://x.example/f",
        &BTreeMap::new(),
        &["@target-uri".into()],
        &params(),
    )
    .unwrap_err();
    assert_eq!(err.kind, Kind::UnsupportedComponent);
    let err = signature_base(
        "GET",
        "https://x.example/f",
        &BTreeMap::new(),
        &["x-absent".into()],
        &params(),
    )
    .unwrap_err();
    assert_eq!(err.kind, Kind::MissingComponent);
    let err = signature_base(
        "GET",
        "/things",
        &BTreeMap::new(),
        &["@authority".into()],
        &params(),
    )
    .unwrap_err();
    assert_eq!(err.kind, Kind::MissingComponent);
}

#[test]
fn optional_parameters_serialize_in_a_fixed_order() {
    let params = SignatureParams {
        created: Some(SIGNED_AT),
        keyid: Some("k".into()),
        alg: Some("ed25519".into()),
        expires: Some(SIGNED_AT + 60),
        nonce: Some("abc".into()),
        tag: Some("app".into()),
    };
    let base = signature_base(
        "GET",
        "https://x.example/f",
        &BTreeMap::new(),
        &["@method".into()],
        &params,
    )
    .unwrap();
    let text = String::from_utf8(base).unwrap();
    assert_eq!(
        text.lines().last().unwrap(),
        r#""@signature-params": ("@method");created=1700000000;expires=1700000060;nonce="abc";alg="ed25519";keyid="k";tag="app""#
    );
}

#[test]
fn sign_and_verify_round_trip() {
    let (k, out) = signed(SignOptions {
        body: Some(BODY.to_vec()),
        ..Default::default()
    });
    assert!(out.contains_key("Content-Digest"));
    let verdict = verify_request(
        "POST",
        URL_QUERY,
        &out,
        &VerifyOptions {
            body: Some(BODY.to_vec()),
            ..opted_out()
        },
    )
    .unwrap();
    assert_eq!(verdict.aid, k.aid());
    assert!(verdict.covered.iter().any(|c| c == "content-digest"));
}

#[test]
fn a_chosen_covered_set_omitting_the_digest_refuses_a_body() {
    let err = sign_request(
        &key(),
        "POST",
        URL_QUERY,
        &BTreeMap::new(),
        &SignOptions {
            body: Some(BODY.to_vec()),
            covered: Some(vec!["@method".into()]),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(err.kind, Kind::UncoveredBody);
}

#[test]
fn a_chosen_covered_set_including_the_digest_signs_a_body() {
    let out = sign_request(
        &key(),
        "POST",
        URL_QUERY,
        &BTreeMap::new(),
        &SignOptions {
            body: Some(BODY.to_vec()),
            covered: Some(vec![
                "@method".into(),
                "@path".into(),
                "content-digest".into(),
            ]),
            created: Some(SIGNED_AT),
            label: Some("mine".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(out["Signature-Input"].starts_with("mine="));
    verify_request(
        "POST",
        URL_QUERY,
        &out,
        &VerifyOptions {
            body: Some(BODY.to_vec()),
            ..opted_out()
        },
    )
    .unwrap();
}

#[test]
fn a_caller_supplied_digest_is_used_rather_than_recomputed() {
    let supplied = headers(&[("Content-Digest", &content_digest(BODY))]);
    let out = sign_request(
        &key(),
        "POST",
        URL_QUERY,
        &supplied,
        &SignOptions {
            body: Some(BODY.to_vec()),
            created: Some(SIGNED_AT),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        !out.contains_key("Content-Digest"),
        "fiki should not echo back a digest it was given"
    );
    let mut all = supplied.clone();
    all.extend(out);
    verify_request(
        "POST",
        URL_QUERY,
        &all,
        &VerifyOptions {
            body: Some(BODY.to_vec()),
            ..opted_out()
        },
    )
    .unwrap();
}

#[test]
fn signing_without_a_created_uses_the_wall_clock() {
    let out = sign_request(
        &key(),
        "GET",
        URL_QUERY,
        &BTreeMap::new(),
        &SignOptions::default(),
    )
    .unwrap();
    verify_request(
        "GET",
        URL_QUERY,
        &out,
        &VerifyOptions {
            max_age: MaxAge::seconds(300),
            ..opted_out()
        },
    )
    .unwrap();
}

#[test]
fn an_expected_aid_is_authoritative_over_the_inline_keyid() {
    let (k, out) = signed(SignOptions::default());
    verify_request(
        "POST",
        URL_QUERY,
        &out,
        &VerifyOptions {
            expected_aid: Some(k.aid()),
            ..opted_out()
        },
    )
    .unwrap();
    let stranger = Key::generate().aid();
    let err = verify_request(
        "POST",
        URL_QUERY,
        &out,
        &VerifyOptions {
            expected_aid: Some(stranger),
            ..opted_out()
        },
    )
    .unwrap_err();
    assert_eq!(err.kind, Kind::SignatureMismatch);
}

#[test]
fn a_malformed_expected_aid_is_refused() {
    let (_, out) = signed(SignOptions::default());
    let err = verify_request(
        "POST",
        URL_QUERY,
        &out,
        &VerifyOptions {
            expected_aid: Some("nope".into()),
            ..opted_out()
        },
    )
    .unwrap_err();
    assert_eq!(err.kind, Kind::MalformedKey);
}

#[test]
fn a_covered_component_the_verifier_cannot_build_is_refused() {
    let (_, mut out) = signed(SignOptions::default());
    out.insert(
        "Signature-Input".into(),
        out["Signature-Input"].replacen(r#"("@method""#, r#"("@target-uri""#, 1),
    );
    let err = verify_request("POST", URL_QUERY, &out, &opted_out()).unwrap_err();
    assert_eq!(err.kind, Kind::UnsupportedComponent);
}

#[test]
fn digest_handling() {
    // An unknown algorithm alongside a known one verifies; only-unknown is refused; a value that
    // is not a byte sequence is refused.
    //
    // A signer refuses to sign a digest the verifier would refuse for its body (@5zrf8gjk), so the
    // refused ones are signed without the body and verified with it.
    for (supplied_digest, expected) in [
        (format!("sha-1=:AAAA:, {}", content_digest(BODY)), None),
        ("sha-1=:AAAA:".to_string(), Some(Kind::MalformedDigest)),
        (
            r#"sha-256="not bytes""#.to_string(),
            Some(Kind::MalformedDigest),
        ),
        ("((( not sfv".to_string(), Some(Kind::MalformedDigest)),
    ] {
        let supplied = headers(&[("Content-Digest", &supplied_digest)]);
        let opts = SignOptions {
            body: Some(BODY.to_vec()),
            created: Some(SIGNED_AT),
            covered: Some(
                ["@method", "@authority", "@path", "@query", "content-digest"]
                    .map(String::from)
                    .to_vec(),
            ),
            ..Default::default()
        };
        let signing = sign_request(&key(), "POST", URL_QUERY, &supplied, &opts);
        if expected.is_some() {
            assert_eq!(
                signing.unwrap_err().kind,
                Kind::InvalidArgument,
                "{supplied_digest}"
            );
        }
        let out = sign_request(
            &key(),
            "POST",
            URL_QUERY,
            &supplied,
            &SignOptions { body: None, ..opts },
        )
        .unwrap();
        let mut all = supplied.clone();
        all.extend(out);
        let result = verify_request(
            "POST",
            URL_QUERY,
            &all,
            &VerifyOptions {
                body: Some(BODY.to_vec()),
                ..opted_out()
            },
        );
        match expected {
            None => {
                result.unwrap_or_else(|e| panic!("{supplied_digest} should verify: {e}"));
            }
            Some(kind) => assert_eq!(result.unwrap_err().kind, kind, "{supplied_digest}"),
        }
    }
}

#[test]
fn a_sha512_digest_is_computed_and_compared() {
    use sha2::{Digest, Sha512};
    let sum = Sha512::digest(BODY);
    let encoded = {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in sum.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                A[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                A[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    };
    let supplied = headers(&[("Content-Digest", &format!("sha-512=:{encoded}:"))]);
    let out = sign_request(
        &key(),
        "POST",
        URL_QUERY,
        &supplied,
        &SignOptions {
            body: Some(BODY.to_vec()),
            created: Some(SIGNED_AT),
            ..Default::default()
        },
    )
    .unwrap();
    let mut all = supplied.clone();
    all.extend(out);
    verify_request(
        "POST",
        URL_QUERY,
        &all,
        &VerifyOptions {
            body: Some(BODY.to_vec()),
            ..opted_out()
        },
    )
    .unwrap();
}

#[test]
fn freshness() {
    let check = |now: i64, max_age: MaxAge, skew: Option<i64>| {
        let (_, out) = signed(SignOptions::default());
        verify_request(
            "POST",
            URL_QUERY,
            &out,
            &VerifyOptions {
                max_age,
                skew,
                now: Some(now),
                ..opted_out()
            },
        )
    };
    check(SIGNED_AT + 299, MaxAge::seconds(300), None).expect("inside max age");
    check(SIGNED_AT + 303, MaxAge::seconds(300), None).expect("skew is tolerated");
    assert_eq!(
        check(SIGNED_AT + 400, MaxAge::seconds(300), None)
            .unwrap_err()
            .kind,
        Kind::SignatureTooOld
    );
    assert_eq!(
        check(SIGNED_AT + 302, MaxAge::seconds(300), Some(1))
            .unwrap_err()
            .kind,
        Kind::SignatureTooOld
    );
    assert_eq!(
        check(SIGNED_AT - 60, MaxAge::seconds(300), None)
            .unwrap_err()
            .kind,
        Kind::SignatureTooOld
    );
    check(SIGNED_AT + 1_000_000, MaxAge::Unchecked, None).expect("declining the check declines it");
}

#[test]
fn expires_is_enforced_even_when_max_age_is_declined() {
    let (_, out) = signed(SignOptions {
        expires: Some(SIGNED_AT + 60),
        ..Default::default()
    });
    verify_request(
        "POST",
        URL_QUERY,
        &out,
        &VerifyOptions {
            now: Some(SIGNED_AT + 30),
            ..opted_out()
        },
    )
    .expect("before its expiry");
    let err = verify_request(
        "POST",
        URL_QUERY,
        &out,
        &VerifyOptions {
            now: Some(SIGNED_AT + 66),
            ..opted_out()
        },
    )
    .unwrap_err();
    assert_eq!(err.kind, Kind::SignatureExpired);
}

#[test]
fn a_request_signed_with_a_lowercase_method_does_not_verify_as_uppercase() {
    let out = sign_request(
        &key(),
        "post",
        URL_QUERY,
        &BTreeMap::new(),
        &SignOptions {
            created: Some(SIGNED_AT),
            ..Default::default()
        },
    )
    .unwrap();
    verify_request("post", URL_QUERY, &out, &opted_out()).unwrap();
    let err = verify_request("POST", URL_QUERY, &out, &opted_out()).unwrap_err();
    assert_eq!(err.kind, Kind::SignatureMismatch);
}

#[test]
fn a_target_is_origin_form_or_absolute_with_an_authority() {
    // `this.i` @524c8qgv, "A target beginning with a slash is origin-form": a caller error when
    // signing, whatever else is wrong with it.
    let host = [("Host", "api.example.com")];
    for url in [
        "http:/x",
        "https:///x",
        "https://?q",
        "mailto:x",
        "api.example.com:443",
        "*",
        "://api.example.com/x",
        "1http://api.example.com/x",
        "",
        "/x#",
    ] {
        let err = signature_base(
            "GET",
            url,
            &headers(&host),
            &["@path".to_string()],
            &params(),
        )
        .unwrap_err();
        assert_eq!(err.kind, Kind::InvalidArgument, "{url:?}");
    }
    // A target beginning with a slash is a path however many slashes follow, so "//evil.example"
    // is not an authority and Host stays the authority.
    assert_eq!(
        line("@path", "GET", "//evil.example/p?q", &host),
        r#""@path": //evil.example/p"#
    );
    assert_eq!(
        line("@authority", "GET", "//evil.example/p", &host),
        r#""@authority": api.example.com"#
    );
    // Host keeps its port, even one that would be a default, since without a scheme none is.
    assert_eq!(
        line(
            "@authority",
            "GET",
            "/p",
            &[("Host", "API.example.com:443")]
        ),
        r#""@authority": api.example.com:443"#
    );
    // A component read from no part of the target does not need it to be readable.
    assert_eq!(line("@method", "GET", "http:/x", &[]), r#""@method": GET"#);
    for bad in [
        "api.example.com:65536",
        "a@api.example.com",
        "a.example, b.example",
        "[::g]",
    ] {
        let err = signature_base(
            "GET",
            "/p",
            &headers(&[("Host", bad)]),
            &["@authority".to_string()],
            &params(),
        )
        .unwrap_err();
        assert_eq!(err.kind, Kind::InvalidArgument, "{bad:?}");
    }
}

#[test]
fn authorities_built_from_a_list_of_hosts() {
    assert_eq!(
        fiki::Authorities::served(["api.example.com", "b.example"]),
        fiki::Authorities::Served(
            ["api.example.com".to_string(), "b.example".to_string()]
                .into_iter()
                .collect()
        )
    );
    assert_eq!(fiki::Minimum::default(), fiki::Minimum::Default);
    assert_eq!(fiki::Authorities::default(), fiki::Authorities::Unstated);
    assert_eq!(
        fiki::DEFAULT_MINIMUM,
        ["@method", "@authority", "@path", "@query"]
    );
}

#[test]
fn to_aid_of_anything_but_32_bytes_is_a_caller_error() {
    // Review B8: it indexed a 33-byte buffer with whatever it was handed, and panicked.
    for length in [0, 1, 31, 33, 64] {
        let refused = fiki::to_aid(&vec![7u8; length]).unwrap_err();
        assert_eq!(refused.kind, Kind::InvalidArgument, "{length}");
        assert!(refused.message.contains(&length.to_string()), "{length}");
    }
    assert_eq!(fiki::to_aid(&[0u8; 32]).unwrap().len(), 44);
}

#[test]
fn an_error_quotes_at_most_64_characters_of_an_untrusted_url_and_escapes_controls() {
    // Review A9, B9: a 5 MB URL made a 10 MB error carrying the URL twice, in the message and the
    // detail (`this.i` @524c8qgv).
    let signed = sign_request(
        &key(),
        "GET",
        "https://api.example.com/x",
        &BTreeMap::new(),
        &SignOptions {
            created: Some(SIGNED_AT),
            ..Default::default()
        },
    )
    .unwrap();
    let url = format!("https://api.example.com/{}", "p".repeat(9000));
    let refused = verify_request("GET", &url, &signed, &opted_out()).unwrap_err();
    assert_eq!(refused.kind, Kind::SignatureMismatch);
    assert!(refused.message.len() < 400, "{}", refused.message);
    assert!(
        refused.message.contains("cut from 9024 characters"),
        "{}",
        refused.message
    );
    assert!(refused.detail.as_deref().is_some_and(|d| d.len() < 120));

    let refused = verify_request(
        "GET",
        "https://api.example.com/a\x1bb",
        &signed,
        &opted_out(),
    )
    .unwrap_err();
    assert!(!refused.message.contains('\x1b'), "{}", refused.message);
    assert!(refused.message.contains("\\u{1b}"), "{}", refused.message);
    assert!(!refused.detail.unwrap().contains('\x1b'));

    // A Host over the bound, and one under it holding a control character, are quoted the same way.
    for host in ["h".repeat(9000), "a\x07.example".to_string()] {
        let refused =
            verify_request("GET", "/x", &headers(&[("Host", &host)]), &opted_out()).unwrap_err();
        assert!(refused.message.len() < 400, "{}", refused.message);
        assert!(!refused.message.contains('\x07'), "{}", refused.message);
    }
}

#[test]
fn an_empty_expected_keyid_is_a_caller_error_in_both_verifiers() {
    // "" names no AID, and reading it as the decline would turn a missing value into "accept any
    // signer" (`this.i` @524c8qgv, part-two refinements).
    let empty = VerifyOptions {
        expected_keyid: ExpectedKeyid::Is(String::new()),
        ..opted_out()
    };
    let refused = verify_request("GET", URL_QUERY, &BTreeMap::new(), &empty).unwrap_err();
    assert_eq!(refused.kind, Kind::InvalidArgument);
    let refused = verify_response(200, &BTreeMap::new(), None, &empty).unwrap_err();
    assert_eq!(refused.kind, Kind::InvalidArgument);
    // Unstated is refused only for a response; a request verifier has a key policy of its own.
    let unstated = VerifyOptions {
        expected_keyid: ExpectedKeyid::Unstated,
        ..opted_out()
    };
    let refused = verify_response(200, &BTreeMap::new(), None, &unstated).unwrap_err();
    assert_eq!(refused.kind, Kind::InvalidArgument);
    assert_eq!(
        verify_request("GET", URL_QUERY, &BTreeMap::new(), &unstated)
            .unwrap_err()
            .kind,
        Kind::MissingSignature
    );
    assert_eq!(ExpectedKeyid::is("B-x"), ExpectedKeyid::Is("B-x".into()));
}

#[test]
fn userinfo_is_a_caller_error_when_signing() {
    // RFC 9110 section 4.2.4 (`this.i` @524c8qgv): refused, never stripped. refusals.json pins the
    // verifier's side.
    for url in [
        "https://user@api.example.com/x",
        "https://@api.example.com/x",
        "https://:@api.example.com/x",
    ] {
        let refused = sign_request(
            &key(),
            "GET",
            url,
            &BTreeMap::new(),
            &SignOptions::default(),
        )
        .unwrap_err();
        assert_eq!(refused.kind, Kind::InvalidArgument, "{url}");
    }
}

#[test]
fn a_covered_field_value_is_bounded_inclusively_before_it_is_trimmed() {
    let sign = |value: &str| {
        sign_request(
            &key(),
            "GET",
            URL_QUERY,
            &headers(&[("X-Note", value)]),
            &SignOptions {
                covered: Some(vec!["@method".into(), "x-note".into()]),
                ..Default::default()
            },
        )
    };
    assert!(sign(&"n".repeat(fiki::MAX_FIELD_BYTES)).is_ok());
    assert_eq!(
        sign(&"n".repeat(fiki::MAX_FIELD_BYTES + 1))
            .unwrap_err()
            .kind,
        Kind::SignatureMismatch
    );
    // Over the bound only with its optional whitespace, which is measured too.
    let padded = format!(" {} ", "n".repeat(fiki::MAX_FIELD_BYTES - 1));
    assert_eq!(sign(&padded).unwrap_err().kind, Kind::SignatureMismatch);
    // Measured in bytes, not characters.
    let wide = "é".repeat(fiki::MAX_FIELD_BYTES / 2 + 1);
    assert_eq!(sign(&wide).unwrap_err().kind, Kind::SignatureMismatch);
}

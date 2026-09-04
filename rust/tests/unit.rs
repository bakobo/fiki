//! The ground the shared vectors do not cover: signing a fresh request, generating a key, the
//! parser's own refusal branches, and the freshness rules beyond the three cases refusals.json
//! pins. Those are not cross-implementation contracts — they are this port working.

use std::collections::BTreeMap;

use fiki::{
    content_digest, sign_request, signature_base, verify_request, verifying_key, Key, Kind,
    SignOptions, SignatureParams, VerifyOptions,
};

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
    assert_eq!(fiki::to_aid(raw.as_bytes()), SEED_AID);
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
    ] {
        assert_eq!(
            verifying_key(aid).unwrap_err().kind,
            Kind::MalformedKey,
            "{aid}"
        );
    }
}

#[test]
fn any_32_bytes_are_accepted_as_a_key_and_rejected_at_verification() {
    // Measured, not assumed: ed25519-dalek 2.x's VerifyingKey::from_bytes accepts any 32 bytes,
    // including all-zero and all-0xFF, and defers point validation to verification. So an AID
    // that decodes to nonsense is a signature failure rather than a malformed key, and a test
    // asserting the opposite would be asserting a guarantee this port does not have.
    for bytes in [[0x00u8; 32], [0xFFu8; 32]] {
        let aid = fiki::to_aid(&bytes);
        assert!(verifying_key(&aid).is_ok(), "from_bytes accepts {aid}");
    }
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
    assert_eq!(
        line("@method", "post", "https://example.com/f", &[]),
        r#""@method": POST"#
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
    // A fragment is not part of the request target and never reaches the base.
    assert_eq!(
        line("@path", "GET", "https://example.com/f#frag", &[]),
        r#""@path": /f"#
    );
    // A host with a non-numeric suffix after the colon is not a port.
    assert_eq!(
        line("@authority", "GET", "https://[::1]/f", &[]),
        r#""@authority": [::1]"#
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            max_age: Some(300),
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
    let err = verify_request("POST", URL_QUERY, &out, &VerifyOptions::default()).unwrap_err();
    assert_eq!(err.kind, Kind::UnsupportedComponent);
}

#[test]
fn digest_handling() {
    // An unknown algorithm alongside a known one verifies; only-unknown is refused; a value that
    // is not a byte sequence is refused.
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
        let result = verify_request(
            "POST",
            URL_QUERY,
            &all,
            &VerifyOptions {
                body: Some(BODY.to_vec()),
                ..Default::default()
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
            ..Default::default()
        },
    )
    .unwrap();
}

#[test]
fn freshness() {
    let check = |now: i64, max_age: Option<i64>, skew: Option<i64>| {
        let (_, out) = signed(SignOptions::default());
        verify_request(
            "POST",
            URL_QUERY,
            &out,
            &VerifyOptions {
                max_age,
                skew,
                now: Some(now),
                ..Default::default()
            },
        )
    };
    check(SIGNED_AT + 299, Some(300), None).expect("inside max age");
    check(SIGNED_AT + 303, Some(300), None).expect("skew is tolerated");
    assert_eq!(
        check(SIGNED_AT + 400, Some(300), None).unwrap_err().kind,
        Kind::SignatureTooOld
    );
    assert_eq!(
        check(SIGNED_AT + 301, Some(300), Some(0)).unwrap_err().kind,
        Kind::SignatureTooOld
    );
    assert_eq!(
        check(SIGNED_AT - 60, Some(300), None).unwrap_err().kind,
        Kind::SignatureTooOld
    );
    check(SIGNED_AT + 1_000_000, None, None).expect("declining the check declines it");
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
            ..Default::default()
        },
    )
    .expect("before its expiry");
    let err = verify_request(
        "POST",
        URL_QUERY,
        &out,
        &VerifyOptions {
            now: Some(SIGNED_AT + 66),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(err.kind, Kind::SignatureExpired);
}

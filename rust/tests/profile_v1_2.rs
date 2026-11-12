//! What KERI profile version 1.2 asks of fiki beyond 1.1 (`this.i` @37rktct3, @84nt4je0).
//!
//! The port of fiki-py's `py/tests/test_profile_v1_2.py`. Two rules, each a library behaviour
//! rather than vector data. Under a resolver, where the keyid is an AID, a `B` keyid's key is the
//! prefix's and must lie in the prime-order subgroup, and an AID is any of keripy's PreDex prefix
//! codes (@37rktct3). Content no header announced is refused at the body stage, after the signature
//! and freshness checks, so a message with two defects gets one code whichever kind of verifier
//! reads it (@84nt4je0).
//!
//! The mixed-order key is fiki-py's, which that test builds in affine coordinates from the curve
//! equation; this file pins its bytes and checks them with ed25519-dalek's point arithmetic, a
//! different method from the scalar multiple the library's subgroup check uses.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fiki::{
    sign_request, sign_response, verify_request, verify_response, verifying_key, Authorities,
    ExpectedKeyid, Key, Kind, MaxAge, Minimum, Request, Resolver, SignOptions, VerifyOptions,
    REQUEST_MINIMUM,
};
use sha2::{Digest, Sha256, Sha512};

const URL: &str = "https://keria.example.com/identifiers?type=rot";
const BODY: &[u8] = br#"{"hello": "world"}"#;
const AT: i64 = 1_700_000_000;
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// fiki-py's MIXED: the key of seed 0..32 plus a point of order 8, so on the curve, of large
/// order, and outside the prime-order subgroup.
const MIXED: &str = "38fd00c26d1ce27e6f4b55b15fbebffae98052f763b21625375d037af012b0a7";
const B_MIXED: &str = "BDj9AMJtHOJ-b0tVsV--v_rpgFL3Y7IWJTddA3rwErCn";

fn key() -> Key {
    Key::from_seed(&(0u8..32).collect::<Vec<_>>()).unwrap()
}

fn mixed() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&MIXED[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn b64url(raw: &[u8]) -> String {
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
                out.push(B64URL[(n >> shift) as usize & 63] as char);
            }
        }
    }
    out
}

/// CESR's arithmetic: zero bytes in front to a multiple of three, base64url, and the code in place
/// of the characters those bytes became.
fn cesr(code: &str, data: &[u8]) -> String {
    let pad = (3 - data.len() % 3) % 3;
    let mut padded = vec![0u8; pad];
    padded.extend_from_slice(data);
    format!("{code}{}", &b64url(&padded)[pad..])
}

fn e_aid() -> String {
    cesr("E", &Sha256::digest(b"a transferable AID"))
}

fn b_weak() -> String {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    cesr("B", &identity)
}

struct Sent {
    url: String,
    body: Option<Vec<u8>>,
    headers: BTreeMap<String, String>,
}

fn sign(keyid: &str, body: Option<&[u8]>, extra: &[(&str, &str)]) -> Sent {
    let given: BTreeMap<String, String> = extra
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let opts = SignOptions {
        body: body.map(<[u8]>::to_vec),
        created: Some(AT),
        keyid: Some(keyid.to_string()),
        ..Default::default()
    };
    let mut headers = given.clone();
    headers.extend(sign_request(&key(), "POST", URL, &given, &opts).unwrap());
    Sent {
        url: URL.into(),
        body: opts.body,
        headers,
    }
}

fn policy(resolve: Option<Resolver>) -> VerifyOptions {
    VerifyOptions {
        max_age: MaxAge::seconds(300),
        now: Some(AT),
        resolve,
        minimum: Minimum::Off,
        authorities: Authorities::Unchecked,
        expected_keyid: ExpectedKeyid::Unchecked,
        ..Default::default()
    }
}

impl Sent {
    fn verify(&self, opts: VerifyOptions) -> fiki::Result<fiki::Verdict> {
        verify_request(
            "POST",
            &self.url,
            &self.headers,
            &VerifyOptions {
                body: opts.body.clone().or(self.body.clone()),
                ..opts
            },
        )
    }

    fn kind(&self, opts: VerifyOptions) -> Kind {
        self.verify(opts).unwrap_err().kind
    }
}

fn never() -> Resolver {
    Arc::new(|keyid: &str| panic!("the resolver was asked about {keyid}"))
}

/// A resolver that records every keyid it is asked about and knows none of them.
fn recording() -> (Resolver, Arc<Mutex<Vec<String>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = calls.clone();
    let resolver: Resolver = Arc::new(move |keyid: &str| {
        seen.lock().unwrap().push(keyid.to_string());
        Ok(None)
    });
    (resolver, calls)
}

#[test]
fn the_oracle_key_is_on_the_curve_and_not_in_the_prime_order_subgroup() {
    assert_eq!(cesr("B", &mixed()), B_MIXED);
    let point = ed25519_dalek::VerifyingKey::from_bytes(&mixed()).unwrap();
    assert!(!point.is_weak(), "a mixed-order point has large order");
    let honest = verifying_key(&key().aid()).unwrap().to_edwards();
    let torsion = point.to_edwards() - honest;
    assert!(
        torsion.is_small_order(),
        "the difference is a torsion point"
    );
    assert_ne!(
        torsion.compress().to_bytes(),
        {
            let mut identity = [0u8; 32];
            identity[0] = 1;
            identity
        },
        "the torsion component is not the identity"
    );
}

// --- B keyids under a resolver: the prefix's key, never the resolver's (@37rktct3) ---

#[test]
fn a_b_keyid_is_verified_from_its_prefix_without_asking_the_resolver() {
    let sent = sign(&key().aid(), Some(BODY), &[]);
    let verdict = sent.verify(policy(Some(never()))).unwrap();
    assert_eq!(verdict.keyid, Some(key().aid()));
    assert_eq!(verdict.aid, key().aid());
}

#[test]
fn a_mixed_order_b_keyid_is_malformed_under_a_resolver() {
    let sent = sign(B_MIXED, Some(BODY), &[]);
    let err = sent.verify(policy(Some(never()))).unwrap_err();
    assert_eq!(err.kind, Kind::MalformedKey, "{err}");
    assert_eq!(err.detail.as_deref(), Some(B_MIXED));
}

/// An expected AID names its key by an AID as a B keyid does, so the key must lie in the subgroup.
#[test]
fn a_mixed_order_expected_aid_is_malformed() {
    let sent = sign(B_MIXED, Some(BODY), &[]);
    let opts = VerifyOptions {
        expected_aid: Some(B_MIXED.to_string()),
        ..policy(None)
    };
    let err = sent.verify(opts).unwrap_err();
    assert_eq!(err.kind, Kind::MalformedKey, "{err}");
    assert_eq!(err.detail.as_deref(), Some(B_MIXED));
}

#[test]
fn a_weak_b_keyid_is_malformed_before_the_expected_keyid_is_compared() {
    for keyid in [b_weak(), B_MIXED.to_string()] {
        let sent = sign(&keyid, Some(BODY), &[]);
        let opts = VerifyOptions {
            expected_keyid: ExpectedKeyid::is(e_aid()),
            ..policy(Some(never()))
        };
        assert_eq!(sent.kind(opts), Kind::MalformedKey, "{keyid}");
    }
}

#[test]
fn a_mixed_order_key_from_a_resolver_is_malformed() {
    let sent = sign(&e_aid(), Some(BODY), &[]);
    let mixed = mixed();
    let resolver: Resolver = Arc::new(move |_: &str| Ok(Some(mixed)));
    let err = sent.verify(policy(Some(resolver))).unwrap_err();
    assert_eq!(err.kind, Kind::MalformedKey, "{err}");
    assert_eq!(err.detail, Some(e_aid()));
}

#[test]
fn a_mixed_order_key_from_a_resolver_is_refused_before_the_algorithm() {
    let sent = sign(&e_aid(), Some(BODY), &[]);
    let input = sent.headers["Signature-Input"].replace("alg=\"ed25519\"", "alg=\"rsa\"");
    let mut sent = sent;
    sent.headers.insert("Signature-Input".into(), input);
    let mixed = mixed();
    let resolver: Resolver = Arc::new(move |_: &str| Ok(Some(mixed)));
    assert_eq!(sent.kind(policy(Some(resolver))), Kind::MalformedKey);
}

#[test]
fn a_mixed_order_raw_keyid_is_still_fikis_own_lens_and_not_refused_for_its_order() {
    // vectors_format 4 pins acceptance of a mixed-order raw keyid (@5r75ff4m); only an AID's key
    // must lie in the subgroup, so this one reaches the signature check.
    let sent = sign(&b64url(&mixed()), Some(BODY), &[]);
    assert_eq!(sent.kind(policy(None)), Kind::SignatureMismatch);
}

// --- an AID is any of keripy's PreDex codes (@37rktct3) ---

const PREDEX: [(&str, usize); 18] = [
    ("B", 32),
    ("D", 32),
    ("E", 32),
    ("F", 32),
    ("G", 32),
    ("H", 32),
    ("I", 32),
    ("0D", 64),
    ("0E", 64),
    ("0F", 64),
    ("0G", 64),
    ("1AAA", 33),
    ("1AAB", 33),
    ("1AAI", 33),
    ("1AAJ", 33),
    ("1AAC", 57),
    ("1AAD", 57),
    ("1AAE", 114),
];

const OTHER_NON_TRANSFERABLE: [&str; 3] = ["1AAA", "1AAC", "1AAI"];

/// The kind a keyid is refused with under a recording resolver, and the keyids it was asked about.
fn refused(keyid: &str) -> (Kind, Vec<String>) {
    let (resolver, calls) = recording();
    let kind = sign(keyid, Some(BODY), &[]).kind(policy(Some(resolver)));
    let asked = calls.lock().unwrap().clone();
    (kind, asked)
}

#[test]
fn every_predex_code_spells_a_well_formed_aid() {
    for (code, size) in PREDEX {
        let keyid = if code == "B" {
            // Any 32 bytes are not a key, and a B keyid's key is read; this one is.
            key().aid()
        } else {
            let mut digest = Sha512::digest(code.as_bytes()).to_vec();
            digest.extend_from_slice(&digest.clone());
            cesr(code, &digest[..size])
        };
        assert_eq!(keyid.len(), cesr(code, &vec![0u8; size]).len(), "{code}");
        if code == "B" {
            // Its key is its prefix, so it verifies with no resolver ever asked.
            assert!(sign(&keyid, Some(BODY), &[])
                .verify(policy(Some(never())))
                .is_ok());
        } else {
            let (kind, asked) = refused(&keyid);
            if OTHER_NON_TRANSFERABLE.contains(&code) {
                assert_eq!(kind, Kind::UnsupportedAlgorithm, "{code}");
                assert!(asked.is_empty(), "{code}");
            } else {
                assert_eq!(kind, Kind::UnknownKey, "{code}");
                assert_eq!(asked, vec![keyid.clone()], "{code}");
            }
        }
        for bad in [keyid[..keyid.len() - 1].to_string(), format!("{keyid}A")] {
            let (kind, asked) = refused(&bad);
            assert_eq!(kind, Kind::MalformedKey, "{code}: {bad}");
            assert!(asked.is_empty(), "{code}: {bad}");
        }
    }
}

#[test]
fn other_codes_and_non_canonical_spellings_are_not_aids() {
    let a = |n: usize| "A".repeat(n);
    for keyid in [
        format!("A{}", a(43)),
        format!("J{}", a(43)),
        format!("0A{}", a(86)),
        format!("1AAF{}", a(44)),
        format!("1AAD{}", a(75)),
        format!("0Dg{}", a(85)),
        format!("0DQ{}", a(85)),
        // Not base64url at all, at a length a PreDex code would take.
        format!("E{}+", a(42)),
        format!("1AAB{}=", a(43)),
        "1".into(),
    ] {
        let (kind, asked) = refused(&keyid);
        assert_eq!(kind, Kind::MalformedKey, "{keyid}");
        assert!(asked.is_empty(), "{keyid}");
    }
}

#[test]
fn an_ed448_transferable_keyid_with_no_key_state_is_an_unknown_key() {
    let keyid = cesr("1AAD", &(0u8..57).collect::<Vec<_>>());
    let (kind, asked) = refused(&keyid);
    assert_eq!(kind, Kind::UnknownKey);
    assert_eq!(asked, vec![keyid]);
}

#[test]
fn a_non_transferable_keyid_other_than_b_is_an_unsupported_algorithm() {
    for (code, size) in [("1AAA", 33), ("1AAC", 57), ("1AAI", 33)] {
        let mut data = vec![2u8];
        data.extend(0..size as u8 - 1);
        let keyid = cesr(code, &data);
        let err = sign(&keyid, Some(BODY), &[])
            .verify(policy(Some(never())))
            .unwrap_err();
        assert_eq!(err.kind, Kind::UnsupportedAlgorithm, "{code}: {err}");
    }
}

#[test]
fn a_non_transferable_keyid_other_than_the_expected_one_is_unknown_first() {
    let mut data = vec![2u8];
    data.extend(0..32u8);
    let keyid = cesr("1AAA", &data);
    let opts = VerifyOptions {
        expected_keyid: ExpectedKeyid::is(e_aid()),
        ..policy(Some(never()))
    };
    assert_eq!(sign(&keyid, Some(BODY), &[]).kind(opts), Kind::UnknownKey);
}

// --- content no header announced, at the body stage (@84nt4je0) ---

fn floor() -> VerifyOptions {
    VerifyOptions {
        minimum: Minimum::of(REQUEST_MINIMUM),
        ..policy(Some(never()))
    }
}

#[test]
fn an_unannounced_uncovered_request_body_is_refused_at_the_body_stage() {
    let sent = sign(&key().aid(), None, &[]);
    let opts = VerifyOptions {
        body: Some(BODY.to_vec()),
        ..floor()
    };
    assert_eq!(sent.kind(opts), Kind::InsufficientCoverage);
}

#[test]
fn an_unannounced_uncovered_request_body_comes_after_freshness() {
    let sent = sign(&key().aid(), None, &[]);
    let opts = VerifyOptions {
        body: Some(BODY.to_vec()),
        now: Some(AT + 1000),
        ..floor()
    };
    assert_eq!(sent.kind(opts), Kind::SignatureTooOld);
}

#[test]
fn an_unannounced_uncovered_request_body_comes_after_the_signature() {
    let mut sent = sign(&key().aid(), None, &[]);
    let input = sent.headers["Signature-Input"].replace(&format!("created={AT}"), "created=1");
    sent.headers.insert("Signature-Input".into(), input);
    let opts = VerifyOptions {
        body: Some(BODY.to_vec()),
        max_age: MaxAge::Unchecked,
        ..floor()
    };
    assert_eq!(sent.kind(opts), Kind::SignatureMismatch);
}

#[test]
fn an_announced_uncovered_request_body_is_still_refused_at_the_covered_list() {
    let sent = sign(&key().aid(), None, &[("Content-Length", "18")]);
    let opts = VerifyOptions {
        now: Some(AT + 1000),
        ..floor()
    };
    assert_eq!(sent.kind(opts), Kind::InsufficientCoverage);
}

#[test]
fn an_empty_request_body_needs_no_digest() {
    let sent = sign(&key().aid(), None, &[]);
    let opts = VerifyOptions {
        body: Some(Vec::new()),
        ..floor()
    };
    assert!(sent.verify(opts).is_ok());
}

#[test]
fn an_uncovered_response_body_is_refused_at_the_covered_list_by_its_content() {
    // A client holds the response's content before verifying it, so the covered-list check judges
    // it there, ahead of the signature (profile section 9, step 12).
    let request = Request {
        method: "GET".into(),
        url: URL.into(),
        headers: BTreeMap::new(),
        body: None,
    };
    let headers = sign_response(
        &key(),
        200,
        Some(&request),
        &BTreeMap::new(),
        &SignOptions {
            created: Some(AT),
            keyid: Some(key().aid()),
            ..Default::default()
        },
    )
    .unwrap();
    let opts = VerifyOptions {
        body: Some(br#"{"done": true}"#.to_vec()),
        expected_keyid: ExpectedKeyid::is(key().aid()),
        minimum: Minimum::Default,
        ..policy(Some(never()))
    };
    let err = verify_response(201, &headers, Some(&request), &opts).unwrap_err();
    assert_eq!(err.kind, Kind::InsufficientCoverage, "{err}");
}

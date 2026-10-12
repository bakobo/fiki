//! The key-spelling vectors, `vectors/keys/keys.json` (`this.i` @0mvgkwnl).
//!
//! `aid_from` turns any of the public-key spellings into the canonical AID, and `Key::from_openssh`
//! loads an unencrypted OpenSSH private key. Neither touches the wire: a fiki-signed request still
//! carries the raw key in its keyid (@7xrx5evg), and a verifier still compares AIDs.

use std::collections::BTreeMap;
use std::fs;

use fiki::{
    aid_from, sign_request, verify_request, Authorities, ExpectedKeyid, Key, Kind, MaxAge, Minimum,
    SignOptions, VerifyOptions, KEY_VECTORS_FORMAT,
};
use serde_json::Value;

fn vectors() -> Value {
    let path = format!("{}/../vectors/keys/keys.json", env!("CARGO_MANIFEST_DIR"));
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("the key vectors are not where every port reaches them: {path}: {e}")
    });
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("keys.json: {e}"))
}

/// Every section's case count, read once from keys.json when this driver was written and never at
/// test time, so a section emptied or cut short fails here rather than passing on what it still
/// holds.
const CASE_COUNTS: [(&str, &str, usize); 4] = [
    ("public", "accepts", 18),
    ("public", "refusals", 72),
    ("private", "accepts", 7),
    ("private", "refusals", 43),
];

/// Runs every case of one section and reports all the failures together. The section must hold
/// exactly its pinned number of cases, and every one of them must run.
fn each(
    data: &Value,
    section: &str,
    kind: &str,
    mut check: impl FnMut(&Value) -> Result<(), String>,
) {
    let pinned = CASE_COUNTS
        .iter()
        .find(|(s, k, _)| *s == section && *k == kind)
        .unwrap_or_else(|| panic!("{section} {kind} has no pinned case count"))
        .2;
    let cases = data[section][kind].as_array().unwrap();
    assert_eq!(
        cases.len(),
        pinned,
        "{section} {kind} holds {} cases, and {pinned} are pinned",
        cases.len()
    );
    let mut ran = 0;
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| {
            ran += 1;
            check(case)
                .err()
                .map(|why| format!("{}: {why}", case["id"].as_str().unwrap()))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(
        ran, pinned,
        "{section} {kind}: {ran} of its {pinned} cases ran"
    );
}

fn case<'a>(data: &'a Value, section: &str, kind: &str, id: &str) -> &'a Value {
    data[section][kind]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("{section} {kind} has no case {id}"))
}

fn input(case: &Value) -> &str {
    case["input"].as_str().unwrap()
}

/// Every maximal run of `text` made only of characters `allowed` accepts and at least `min` long.
fn runs(text: &str, min: usize, allowed: impl Fn(char) -> bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in text.chars().chain(std::iter::once('\0')) {
        if allowed(c) {
            current.push(c);
        } else {
            if current.chars().count() >= min {
                out.push(current.clone());
            }
            current.clear();
        }
    }
    out
}

fn b64ish(c: char) -> bool {
    c.is_ascii_alphanumeric() || "+/=".contains(c)
}

fn b64url_ish(c: char) -> bool {
    b64ish(c) || "_-".contains(c)
}

/// Whether `error` carries `text`, or any run of it long enough to hold key material, either in
/// its message or in the structural detail a consumer might log.
fn echoes(error: &fiki::Error, text: &str) -> bool {
    let message = error.to_string();
    let whole = text.chars().count() >= 12 && message.contains(text);
    error.detail.is_some()
        || whole
        || runs(text, 12, b64url_ish)
            .iter()
            .any(|run| message.contains(run.as_str()))
}

/// A refusal's message is bounded and holds no control character, as every fiki error is.
fn well_formed(error: &fiki::Error) -> Result<(), String> {
    let message = error.to_string();
    if message.chars().count() > 1024 {
        return Err("its message is over 1024 characters".into());
    }
    if message.chars().any(|c| c < ' ' || c == '\x7f') {
        return Err("its message holds a control character".into());
    }
    Ok(())
}

fn b64url(raw: &[u8]) -> String {
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in raw.chunks(3) {
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            n |= (*b as u32) << (16 - 8 * i);
        }
        for i in 0..=chunk.len() {
            out.push(URL[(n >> (18 - 6 * i)) as usize & 63] as char);
        }
    }
    out
}

#[test]
fn the_file_declares_the_format_this_port_satisfies() {
    assert_eq!(
        vectors()["key_vectors_format"].as_u64(),
        Some(KEY_VECTORS_FORMAT as u64)
    );
}

#[test]
fn a_public_spelling_converts_to_its_aid() {
    let data = vectors();
    each(&data, "public", "accepts", |case| {
        let expected = case["aid"].as_str().unwrap();
        match aid_from(input(case)) {
            Ok(aid) if aid == expected => Ok(()),
            Ok(aid) => Err(format!("gave {aid}, expected {expected}")),
            Err(e) => Err(format!("{}: {e}", e.kind)),
        }
    });
}

#[test]
fn a_malformed_public_spelling_is_refused_without_echoing_it() {
    // Never echoed, because what a caller hands aid_from by mistake can be a private key: the .key
    // file instead of the .pub, or a seed in base64url, which is 43 characters like a raw key.
    let data = vectors();
    each(&data, "public", "refusals", |case| {
        if case["error"] != "MalformedKey" {
            return Err(format!("expects {}, not MalformedKey", case["error"]));
        }
        let text = input(case);
        match aid_from(text) {
            Ok(aid) => Err(format!("converted to {aid}")),
            Err(e) if e.kind != Kind::MalformedKey => Err(format!("{}: {e}", e.kind)),
            Err(e) if echoes(&e, text) => Err(format!("its refusal echoes the input: {e}")),
            Err(e) => well_formed(&e),
        }
    });
}

#[test]
fn an_openssh_key_loads_and_signs_as_its_seed() {
    let data = vectors();
    let message = data["signed_message"].as_str().unwrap().to_owned();
    each(&data, "private", "accepts", |case| {
        let key = Key::from_openssh(input(case)).map_err(|e| format!("{}: {e}", e.kind))?;
        if key.aid() != case["aid"].as_str().unwrap() {
            return Err(format!("aid {}", key.aid()));
        }
        let signature = b64url(&key.sign(message.as_bytes()));
        if signature != case["signature"].as_str().unwrap() {
            return Err(format!("signature {signature}"));
        }
        Ok(())
    });
}

#[test]
fn a_malformed_openssh_key_is_refused_without_echoing_it() {
    let data = vectors();
    each(&data, "private", "refusals", |case| {
        if case["error"] != "MalformedKey" {
            return Err(format!("expects {}, not MalformedKey", case["error"]));
        }
        let text = input(case);
        let e = match Key::from_openssh(text) {
            Ok(key) => return Err(format!("loaded as {}", key.aid())),
            Err(e) => e,
        };
        if e.kind != Kind::MalformedKey {
            return Err(format!("{}: {e}", e.kind));
        }
        // A private key never reaches an error: not its text, not any run of its base64 body long
        // enough to carry key material, and not the detail a consumer might log.
        if e.detail.is_some() {
            return Err("its refusal carries a detail".into());
        }
        let message = e.to_string();
        if runs(text, 16, b64ish)
            .iter()
            .any(|run| message.contains(run.as_str()))
        {
            return Err(format!("its refusal echoes the key: {e}"));
        }
        well_formed(&e)
    });
}

#[test]
fn a_weak_key_is_refused_for_its_weakness_whatever_its_spelling() {
    // Not merely refused: refused by the point check, so the spelling parsed and the key reached
    // it (@37wdchu5). A parser bug that refused these earlier would pass the vector alone.
    let data = vectors();
    let weak: Vec<&Value> = data["public"]["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| {
            let id = c["id"].as_str().unwrap();
            id.ends_with("small-order") || id.ends_with("not-on-curve")
        })
        .collect();
    assert_eq!(
        weak.len(),
        6,
        "the weak-key cases this test was written for"
    );
    for case in weak {
        let message = aid_from(input(case)).unwrap_err().to_string();
        assert!(
            message.contains("small order") || message.contains("canonical encoding of a point"),
            "{}: {message}",
            case["id"]
        );
    }
}

#[test]
fn a_private_key_with_a_weak_public_key_is_refused() {
    let data = vectors();
    let text = input(case(&data, "private", "refusals", "public-small-order"));
    let message = Key::from_openssh(text).unwrap_err().to_string();
    assert!(
        message.contains("does not derive") || message.contains("small order"),
        "{message}"
    );
}

#[test]
fn a_canonical_transferable_or_digest_aid_is_told_to_resolve_it() {
    let data = vectors();
    for id in ["aid-transferable", "aid-digest"] {
        let error = aid_from(input(case(&data, "public", "refusals", id))).unwrap_err();
        assert_eq!(error.kind, Kind::MalformedKey);
        assert!(error.message.contains("resolve it"), "{id}: {error}");
    }
}

#[test]
fn a_malformed_d_prefix_is_not_called_an_aid() {
    // Shape before meaning: text that merely starts with D is not told it is a transferable AID.
    let data = vectors();
    for id in ["aid-transferable-not-base64", "aid-transferable-misspelled"] {
        let error = aid_from(input(case(&data, "public", "refusals", id))).unwrap_err();
        assert_eq!(error.kind, Kind::MalformedKey);
        assert!(!error.message.contains("resolve it"), "{id}: {error}");
    }
}

#[test]
fn a_seed_mistaken_for_a_raw_key_is_not_echoed_when_refused() {
    // About half of all seeds, written as 43 characters of base64url, are not a valid point and so
    // are refused by the curve check rather than by the parser. That refusal must not quote it.
    // The seed is chosen by ed25519-dalek's own decompression rather than by asking aid_from.
    let seed = (0u8..=255)
        .map(|n| [n; 32])
        .find(|s| ed25519_dalek::VerifyingKey::from_bytes(s).is_err())
        .unwrap();
    let text = b64url(&seed);
    let error = aid_from(&text).unwrap_err();
    assert_eq!(error.kind, Kind::MalformedKey);
    assert!(
        error
            .message
            .contains("not the canonical encoding of a point"),
        "{error}"
    );
    assert!(!echoes(&error, &text), "{error}");
}

#[test]
fn the_encrypted_refusal_says_to_keep_a_dedicated_key() {
    let data = vectors();
    let text = input(case(&data, "private", "refusals", "encrypted"));
    let error = Key::from_openssh(text).unwrap_err();
    assert!(error.message.contains("dedicated"), "{error}");
}

#[test]
fn an_ssh_key_signs_a_request_that_verifies_against_its_registered_public_line() {
    let data = vectors();
    let key = Key::from_openssh(input(case(&data, "private", "accepts", "ssh-keygen"))).unwrap();
    let registered = aid_from(input(case(&data, "public", "accepts", "ssh-keygen-pub"))).unwrap();
    let url = "https://example.com/x";
    let headers =
        sign_request(&key, "GET", url, &BTreeMap::new(), &SignOptions::default()).unwrap();
    let verdict = verify_request(
        "GET",
        url,
        &headers,
        &VerifyOptions {
            minimum: Minimum::Default,
            authorities: Authorities::Unchecked,
            expected_keyid: ExpectedKeyid::Unchecked,
            max_age: MaxAge::seconds(60),
            expected_aid: Some(registered.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(verdict.aid, registered);
}

#[test]
fn a_lone_input_one_past_each_bound_is_refused_by_its_length() {
    // The bounds count characters, as the other ports do, so a key whose comment is multi-byte is
    // measured the same way in Rust as in Python.
    let public = format!("ssh-ed25519 AAAA {}", "é".repeat(1024 - 17));
    assert_eq!(public.chars().count(), 1024);
    let error = aid_from(&public).unwrap_err();
    assert!(!error.message.contains("at most"), "{error}");
    let error = aid_from(&format!("{public}é")).unwrap_err();
    assert!(error.message.contains("at most 1024"), "{error}");

    let private = "é".repeat(4096);
    let error = Key::from_openssh(&private).unwrap_err();
    assert!(!error.message.contains("over 4096"), "{error}");
    let error = Key::from_openssh(&format!("{private}é")).unwrap_err();
    assert!(error.message.contains("over 4096"), "{error}");
}

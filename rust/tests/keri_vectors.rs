//! The KERI profile's vector set, `vectors/keri/` (`this.i` @8vwrexxc), run the way fiki-py's
//! `py/tests/test_keri_vectors.py` runs it.
//!
//! A separate contract from the shared `vectors/`: its own format number, refusals named by the
//! profile's neutral section 9 codes rather than fiki's kind names, and files read from the
//! repository root rather than copied. Everything this driver needs is in the files; the only thing
//! it adds is the resolver a KERI verifier would back with key event logs, built from the keys
//! table each file carries, and the verifier that applies each file's policy. Both follow
//! `vectors/keri/generate.py`'s `resolver` and `verify`, which fiki-py's driver imports rather than
//! copies; Rust cannot import them, so they are restated here against the rule the files state.
//!
//! The resolver is authoritative (@6g9zjsv9). It derives a non-transferable `B…` keyid's key from
//! the prefix, looks every transferable keyid up in the table, answers `None` for a well-formed AID
//! it has no key state for, refuses a key state with no single effective signer as
//! `UnsupportedSigner`, and refuses a keyid that is not an AID at all. It never decodes a `D…`
//! keyid as a key, which is exactly what one of the vectors is there to catch.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use fiki::{
    response_signature_base, sign_request, signature_base, verify_request, verify_response,
    verifying_key, Authorities, Error, ExpectedKeyid, Key, Kind, MaxAge, Minimum, Request,
    Resolver, SignOptions, SignatureParams, Verdict, VerifyOptions, KERI_VECTORS_FORMAT,
};
use serde::Deserialize;
use serde_json::Value;

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

const FILES: [&str; 5] = [
    "rfc9421.json",
    "requests.json",
    "responses.json",
    "refusals.json",
    "legacy.json",
];

/// fiki's kinds to the profile's section 9 codes: `vectors/keri/generate.py`'s `CODES`, which the
/// files never carry because they name codes, not any implementation's taxonomy. `MissingKey` has
/// no code of its own: keyid is REQUIRED by the profile, so its absence is a malformed input.
fn code(kind: Kind) -> Option<&'static str> {
    Some(match kind {
        Kind::MissingSignature => "missing-signature",
        Kind::MissingSignatureInput => "missing-signature-input",
        Kind::MalformedSignature => "malformed-signature",
        Kind::MalformedSignatureInput => "malformed-signature-input",
        Kind::MissingKey => "malformed-signature-input",
        Kind::MalformedSignatureLabel => "malformed-signature-label",
        Kind::MissingSignatureLabel => "missing-signature-label",
        Kind::MalformedSignatureValue => "malformed-signature-value",
        Kind::DuplicateComponent => "duplicate-component",
        Kind::UnsupportedComponent => "unsupported-component",
        Kind::InsufficientCoverage => "insufficient-coverage",
        Kind::MalformedKey => "malformed-key",
        Kind::UnknownKey => "unknown-key",
        Kind::UnsupportedSigner => "unsupported-signer",
        Kind::UnsupportedAlgorithm => "unsupported-algorithm",
        Kind::MissingComponent => "missing-component",
        Kind::SignatureMismatch => "signature-mismatch",
        Kind::SignatureTooOld => "signature-stale",
        Kind::SignatureExpired => "signature-expired",
        Kind::MalformedDigest => "malformed-digest",
        Kind::DigestMismatch => "digest-mismatch",
        Kind::UncoveredBody => "uncovered-body",
        Kind::Unauthenticated => "unauthenticated",
        // A mistake in the call rather than a defect in a message, so the profile has no code for
        // it; fiki-py raises ValueError and TypeError there, outside its FikiError taxonomy.
        Kind::InvalidArgument => return None,
    })
}

/// Every kind, so the totality check below cannot pass by forgetting one.
const KINDS: [Kind; 24] = [
    Kind::MissingSignature,
    Kind::MissingSignatureInput,
    Kind::MissingSignatureLabel,
    Kind::MissingKey,
    Kind::MissingComponent,
    Kind::UnknownKey,
    Kind::UnsupportedSigner,
    Kind::Unauthenticated,
    Kind::MalformedSignature,
    Kind::MalformedSignatureInput,
    Kind::MalformedSignatureLabel,
    Kind::MalformedSignatureValue,
    Kind::MalformedKey,
    Kind::MalformedDigest,
    Kind::UnsupportedComponent,
    Kind::DuplicateComponent,
    Kind::InsufficientCoverage,
    Kind::UnsupportedAlgorithm,
    Kind::UncoveredBody,
    Kind::SignatureExpired,
    Kind::SignatureTooOld,
    Kind::DigestMismatch,
    Kind::SignatureMismatch,
    Kind::InvalidArgument,
];

fn root() -> String {
    format!("{}/..", env!("CARGO_MANIFEST_DIR"))
}

fn load(name: &str) -> Value {
    let path = format!("{}/vectors/keri/{name}", root());
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("the KERI vectors are not where every port reaches them: {path}: {e}")
    });
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn typed<T: for<'de> Deserialize<'de>>(value: &Value) -> T {
    serde_json::from_value(value.clone()).unwrap()
}

/// Runs every case and reports all the failures together, so one red run names every case that
/// is wrong rather than only the first.
fn each(cases: &Value, mut check: impl FnMut(&Value) -> Result<(), String>) {
    let failures: Vec<String> = cases
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|case| {
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
}

// --- base64, three alphabets' worth, written out as the port's own tests already do ---

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_decode(text: &str, alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut bits: u32 = 0;
    let mut count = 0;
    let mut out = Vec::new();
    for ch in text.bytes() {
        let value = alphabet.iter().position(|a| *a == ch)? as u32;
        bits = bits << 6 | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(out)
}

fn b64_encode(raw: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
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

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// A one-character CESR code over 32 raw bytes: the arithmetic of fiki's own B lens.
fn qb64(code: char, raw: &[u8]) -> String {
    let mut padded = vec![0u8];
    padded.extend_from_slice(raw);
    format!("{code}{}", &b64_encode(&padded, URL, false)[1..])
}

/// The keys rule each file states: 44 characters, a B, D or E code, and 43 base64url characters
/// that decode behind one pad character to 32 bytes with a zero pad byte, so that re-encoding gives
/// back the keyid exactly.
fn well_formed_aid(keyid: &str) -> bool {
    if keyid.len() != 44 || !matches!(keyid.as_bytes()[0], b'B' | b'D' | b'E') {
        return false;
    }
    match b64_decode(&format!("A{}", &keyid[1..]), URL) {
        Some(decoded) if decoded.len() == 33 => {
            qb64(keyid.as_bytes()[0] as char, &decoded[1..]) == keyid
        }
        _ => false,
    }
}

/// The same 32 key bytes, spelled with a non-zero bit in the pad byte the code character replaces.
fn padding_bit_alias(aid: &str) -> String {
    let value = URL.iter().position(|a| *a == aid.as_bytes()[1]).unwrap();
    format!(
        "{}{}{}",
        &aid[..1],
        URL[value ^ 0b010000] as char,
        &aid[2..]
    )
}

fn raw_key(key: &Key) -> [u8; 32] {
    *verifying_key(&key.aid()).unwrap().as_bytes()
}

/// What a KERI verifier's key lookup does, for a keys table: authoritative, never a decode.
fn resolver(keys: &Value) -> Resolver {
    let table: BTreeMap<String, Value> = keys
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["kind"] == "transferable")
        .map(|entry| (entry["keyid"].as_str().unwrap().to_string(), entry.clone()))
        .collect();
    Arc::new(move |keyid: &str| {
        if !well_formed_aid(keyid) {
            return Err(Error::detailed(
                Kind::MalformedKey,
                format!("\"{keyid}\" is not a well-formed AID."),
                keyid,
            ));
        }
        if keyid.starts_with('B') {
            return Ok(Some(*verifying_key(keyid)?.as_bytes()));
        }
        let Some(entry) = table.get(keyid) else {
            return Ok(None);
        };
        match entry["effective_key"].as_str() {
            None => Err(Error::detailed(
                Kind::UnsupportedSigner,
                format!(
                    "The key state of \"{keyid}\" has no single key that satisfies its threshold."
                ),
                keyid,
            )),
            Some(effective) => Ok(Some(
                b64_decode(effective, URL).unwrap().try_into().unwrap(),
            )),
        }
    })
}

fn body_of(message: &Value) -> Option<Vec<u8>> {
    message["body"].as_str().map(|b| b.as_bytes().to_vec())
}

fn headers_of(message: &Value) -> BTreeMap<String, String> {
    typed(&message["headers"])
}

fn as_request(message: &Value) -> Request {
    Request {
        method: message["method"].as_str().unwrap().to_string(),
        url: message["url"].as_str().unwrap().to_string(),
        headers: headers_of(message),
        body: body_of(message),
    }
}

fn strings(value: &Value) -> Vec<String> {
    typed(value)
}

/// The file's policy extended by the case's, as `generate.py`'s `verify` merges them.
fn policy(data: &Value, case: &Value) -> Value {
    let mut merged = data["policy"].clone();
    if let Some(extra) = case["policy"].as_object() {
        for (k, v) in extra {
            merged[k] = v.clone();
        }
    }
    merged
}

/// Verify as a KERI verifier would, under the given policy.
fn verify(
    request: &Value,
    response: Option<&Value>,
    now: i64,
    policy: &Value,
    keys: &Value,
) -> fiki::Result<Verdict> {
    let options = |minimum: &str| VerifyOptions {
        max_age: policy["max_age"]
            .as_i64()
            .map_or(MaxAge::Unchecked, MaxAge::Seconds),
        skew: policy["skew"].as_i64(),
        now: Some(now),
        resolve: Some(resolver(keys)),
        // Where a policy names no keyid the decline is explicit, since a response verifier must
        // state one (`this.i` @524c8qgv).
        expected_keyid: match policy["expected_keyid"].as_str() {
            Some(keyid) => ExpectedKeyid::is(keyid),
            None => ExpectedKeyid::Unchecked,
        },
        minimum: Minimum::Of(strings(&policy[minimum])),
        ..opted_out()
    };
    match response {
        Some(response) => verify_response(
            response["status"].as_u64().unwrap() as u16,
            &headers_of(response),
            Some(&as_request(request)),
            &VerifyOptions {
                body: body_of(response),
                ..options("response_minimum")
            },
        ),
        None => verify_request(
            request["method"].as_str().unwrap(),
            request["url"].as_str().unwrap(),
            &headers_of(request),
            &VerifyOptions {
                body: body_of(request),
                authorities: match policy["authorities"].as_array() {
                    Some(hosts) => Authorities::served(hosts.iter().map(|s| s.as_str().unwrap())),
                    None => Authorities::Unchecked,
                },
                ..options("request_minimum")
            },
        ),
    }
}

fn run(case: &Value, data: &Value) -> fiki::Result<Verdict> {
    verify(
        &case["request"],
        case.get("response"),
        case["now"].as_i64().unwrap(),
        &policy(data, case),
        &data["keys"],
    )
}

/// A component identifier in its RFC 8941 serialized form, as the files spell every one.
fn serialized(spec: &str) -> String {
    if spec.starts_with('"') {
        spec.to_string()
    } else {
        format!("\"{spec}\"")
    }
}

/// The parameters a Signature-Input member carries, read as the files write them: one member,
/// `label=(...)` followed by `;name=value` pairs whose values are integers or quoted strings.
fn signature_params(input: &str) -> SignatureParams {
    let after = &input[input.rfind(')').unwrap() + 1..];
    let mut params = SignatureParams::default();
    for pair in after.split(';').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap();
        let text = value.trim_matches('"').to_string();
        match name {
            "created" => params.created = Some(value.parse().unwrap()),
            "expires" => params.expires = Some(value.parse().unwrap()),
            "nonce" => params.nonce = Some(text),
            "alg" => params.alg = Some(text),
            "keyid" => params.keyid = Some(text),
            "tag" => params.tag = Some(text),
            other => panic!("a parameter the files never carry: {other}"),
        }
    }
    params
}

fn covered_in(input: &str) -> Vec<String> {
    let inner = &input[input.find('(').unwrap() + 1..input.rfind(')').unwrap()];
    inner.split(' ').map(str::to_string).collect()
}

/// The base a signer builds from the parameters its Signature-Input carries, checked against the
/// signature on the message under the resolver's key — `generate.py`'s `expected_base`.
fn expected_base(
    request: &Value,
    response: Option<&Value>,
    keys: &Value,
) -> fiki::Result<(String, String)> {
    let message = response.unwrap_or(request);
    let headers = headers_of(message);
    let input = headers["Signature-Input"].clone();
    let params = signature_params(&input);
    let covered = covered_in(&input);
    let base = match response {
        Some(response) => response_signature_base(
            response["status"].as_u64().unwrap() as u16,
            &headers,
            Some(&as_request(request)),
            &covered,
            &params,
        )?,
        None => signature_base(
            request["method"].as_str().unwrap(),
            request["url"].as_str().unwrap(),
            &headers,
            &covered,
            &params,
        )?,
    };
    let signature = headers["Signature"]
        .split_once('=')
        .unwrap()
        .1
        .trim_matches(':')
        .to_string();
    let key = resolver(keys)(params.keyid.as_deref().unwrap())?.unwrap();
    let raw: [u8; 64] = b64_decode(&signature, STD).unwrap().try_into().unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify(&base, &Signature::from_bytes(&raw))
        .map_err(|_| Error::new(Kind::SignatureMismatch, "the stated base was not signed"))?;
    Ok((String::from_utf8(base).unwrap(), signature))
}

// --- the files themselves ---

#[test]
fn this_port_satisfies_the_keri_vectors_format_it_is_running() {
    // The same guard @4fhrre0m gives the shared set, against its own number (@8vwrexxc).
    assert_eq!(KERI_VECTORS_FORMAT, 5);
    for name in FILES {
        let data = load(name);
        assert_eq!(data["keri_vectors_format"], KERI_VECTORS_FORMAT, "{name}");
        assert!(data.get("vectors_format").is_none(), "{name}");
        assert!(!data["cases"].as_array().unwrap().is_empty(), "{name}");
    }
}

#[test]
fn each_file_names_the_published_profile_it_pins() {
    let doc = fs::read_to_string(format!("{}/docs/keri-profile.md", root())).unwrap();
    for name in FILES {
        let profile = &load(name)["profile"];
        assert_eq!(profile["version"], 1, "{name}");
        assert_eq!(
            profile["where"],
            "https://github.com/bakobo/fiki/blob/main/docs/keri-profile.md"
        );
        let title = profile["title"].as_str().unwrap();
        assert!(
            doc.starts_with(&format!("# {title}\n\nVersion 1, ")),
            "{name}"
        );
    }
}

#[test]
fn each_file_states_the_policy_it_assumes() {
    for name in ["requests.json", "responses.json", "refusals.json"] {
        let policy = &load(name)["policy"];
        assert_eq!(policy["max_age"], 300, "{name}");
        assert_eq!(policy["skew"], 60, "{name}");
        assert_eq!(
            strings(&policy["request_minimum"]),
            ["\"@method\"", "\"@path\"", "\"@query\""]
        );
        assert_eq!(
            strings(&policy["response_minimum"]),
            [
                "\"@status\"",
                "\"@method\";req",
                "\"@path\";req",
                "\"@query\";req"
            ]
        );
    }
}

#[test]
fn the_minimum_sets_are_the_ones_the_files_state() {
    let policy = &load("refusals.json")["policy"];
    let mine = |set: &[&str]| set.iter().map(|s| serialized(s)).collect::<Vec<_>>();
    assert_eq!(
        mine(&fiki::REQUEST_MINIMUM),
        strings(&policy["request_minimum"])
    );
    assert_eq!(
        mine(&fiki::RESPONSE_MINIMUM),
        strings(&policy["response_minimum"])
    );
}

#[test]
fn the_keys_table_agrees_with_its_seeds_and_key_states() {
    // A table entry that disagrees with its own seed would make every case using it a lie.
    for name in ["requests.json", "responses.json", "refusals.json"] {
        let data = load(name);
        assert!(data["keys_rule"].as_str().is_some_and(|r| !r.is_empty()));
        for entry in data["keys"].as_array().unwrap() {
            let keyid = entry["keyid"].as_str().unwrap();
            assert!(well_formed_aid(keyid), "{keyid}");
            let signer = Key::from_seed(&from_hex(entry["seed_hex"].as_str().unwrap())).unwrap();
            if entry["kind"] == "non-transferable" {
                assert_eq!(keyid, signer.aid());
                continue;
            }
            let state: Vec<Vec<u8>> = entry["key_state"]["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| {
                    let k = k.as_str().unwrap();
                    assert!(k.starts_with('D') && k.len() == 44, "{k}");
                    b64_decode(&format!("A{}", &k[1..]), URL).unwrap()[1..].to_vec()
                })
                .collect();
            match entry["effective_key"].as_str() {
                None => assert_eq!(raw_key(&signer).to_vec(), state[0]),
                Some(effective) => {
                    assert_eq!(b64_decode(effective, URL).unwrap(), raw_key(&signer));
                    assert!(state.contains(&raw_key(&signer).to_vec()));
                }
            }
        }
    }
}

#[test]
fn the_well_formedness_rule_refuses_near_misses() {
    assert!(!well_formed_aid(&format!("E{}", "!".repeat(43))));
    assert!(!well_formed_aid(&format!("A{}", "A".repeat(43))));
    assert!(!well_formed_aid("not-an-aid"));
    for entry in load("requests.json")["keys"].as_array().unwrap() {
        let keyid = entry["keyid"].as_str().unwrap();
        assert!(well_formed_aid(keyid));
        assert!(!well_formed_aid(&padding_bit_alias(keyid)), "{keyid}");
    }
}

#[test]
fn every_refusal_names_a_profile_code_and_every_profile_code_is_exercised() {
    let data = load("refusals.json");
    let named: BTreeSet<String> = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["error"].as_str().unwrap().to_string())
        .collect();
    let codes: BTreeSet<String> = strings(&data["codes"]).into_iter().collect();
    assert_eq!(named, codes);
    for kind in KINDS {
        if let Some(code) = code(kind) {
            assert!(named.contains(code), "{kind}: {code}");
        }
    }
}

#[test]
fn every_kind_has_a_profile_code_except_a_caller_error() {
    // The totality heti's boundary test enforces (@8zw78n0v), against the profile's codes. KINDS
    // must list every variant; a match without a wildcard is what keeps that honest.
    for kind in KINDS {
        let exhaustive = match kind {
            Kind::MissingSignature
            | Kind::MissingSignatureInput
            | Kind::MissingSignatureLabel
            | Kind::MissingKey
            | Kind::MissingComponent
            | Kind::UnknownKey
            | Kind::UnsupportedSigner
            | Kind::Unauthenticated
            | Kind::MalformedSignature
            | Kind::MalformedSignatureInput
            | Kind::MalformedSignatureLabel
            | Kind::MalformedSignatureValue
            | Kind::MalformedKey
            | Kind::MalformedDigest
            | Kind::UnsupportedComponent
            | Kind::DuplicateComponent
            | Kind::InsufficientCoverage
            | Kind::UnsupportedAlgorithm
            | Kind::UncoveredBody
            | Kind::SignatureExpired
            | Kind::SignatureTooOld
            | Kind::DigestMismatch
            | Kind::SignatureMismatch => code(kind).is_some(),
            Kind::InvalidArgument => code(kind).is_none(),
        };
        assert!(exhaustive, "{kind}");
    }
    let unique: BTreeSet<Kind> = KINDS.into_iter().collect();
    assert_eq!(unique.len(), KINDS.len());
}

#[test]
fn the_refusal_codes_are_neutral_rather_than_fiki_kind_names() {
    let names: BTreeSet<String> = KINDS.iter().map(|k| k.to_string()).collect();
    for case in load("refusals.json")["cases"].as_array().unwrap() {
        let error = case["error"].as_str().unwrap();
        assert_eq!(error, error.to_lowercase());
        assert!(!names.contains(error));
    }
}

// --- RFC 9421 B.2.6, which anchors the set to something no Bakobo party wrote ---

#[test]
fn rfc_9421_b_2_6_is_reproduced() {
    each(&load("rfc9421.json")["cases"], |case| {
        let request = &case["request"];
        let base = signature_base(
            request["method"].as_str().unwrap(),
            request["url"].as_str().unwrap(),
            &headers_of(request),
            &strings(&case["covered"]),
            &SignatureParams {
                created: case["created"].as_i64(),
                keyid: case["keyid"].as_str().map(str::to_string),
                ..Default::default()
            },
        )
        .map_err(|e| e.to_string())?;
        let text = String::from_utf8(base.clone()).unwrap();
        if text != case["expected"]["base"] {
            return Err(format!("base {text:?}"));
        }
        let key = Key::from_seed(&from_hex(case["seed_hex"].as_str().unwrap())).unwrap();
        let signature = b64_encode(&key.sign(&base), STD, true);
        if signature != case["expected"]["signature"] {
            return Err(format!("signature {signature}"));
        }
        Ok(())
    });
}

// --- the accept cases ---

fn accepted(case: &Value, data: &Value) -> Result<(), String> {
    let verdict = run(case, data).map_err(|e| format!("{}: {e}", e.kind))?;
    let expected = &case["expected"];
    if verdict.keyid.as_deref() != expected["keyid"].as_str() {
        return Err(format!("keyid {:?}", verdict.keyid));
    }
    let covered: Vec<String> = verdict.covered.iter().map(|c| serialized(c)).collect();
    if covered != strings(&expected["covered"]) {
        return Err(format!("covered {covered:?}"));
    }
    let (base, signature) = expected_base(&case["request"], case.get("response"), &data["keys"])
        .map_err(|e| format!("{}: {e}", e.kind))?;
    if base != expected["base"] || signature != expected["signature"] {
        return Err(format!("base {base:?} / {signature}"));
    }
    Ok(())
}

#[test]
fn request_accept_vectors() {
    let data = load("requests.json");
    each(&data["cases"], |case| accepted(case, &data));
}

#[test]
fn response_accept_vectors() {
    let data = load("responses.json");
    each(&data["cases"], |case| {
        // The request each response answers must itself be one a verifier accepts.
        verify(
            &case["request"],
            None,
            case["now"].as_i64().unwrap(),
            &data["policy"],
            &data["keys"],
        )
        .map_err(|e| format!("its request: {}: {e}", e.kind))?;
        accepted(case, &data)
    });
}

#[test]
fn the_sha_512_cases_are_marked_verify_only() {
    let data = load("requests.json");
    let verify_only: BTreeSet<String> = strings(&data["verify_only"]).into_iter().collect();
    let ids: BTreeSet<String> = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect();
    assert!(verify_only.is_subset(&ids));
    for case in data["cases"].as_array().unwrap() {
        let digest = case["request"]["headers"]["Content-Digest"]
            .as_str()
            .unwrap_or("");
        if !digest.is_empty() && !digest.starts_with("sha-256=") || digest.contains(',') {
            assert!(verify_only.contains(case["id"].as_str().unwrap()));
        }
    }
}

// --- the refusals ---

#[test]
fn refusal_vectors() {
    // Each case has one defect and so one correct code under the profile's section 9 order.
    let data = load("refusals.json");
    each(&data["cases"], |case| {
        let expected = case["error"].as_str().unwrap();
        if case["verified_by_fiki"] == false {
            // Carried as data (@4tkkp50h): fiki has no legacy mode to detect it with.
            return match (expected, case["why"].as_str()) {
                ("mode-mismatch", Some(why)) if !why.is_empty() => Ok(()),
                _ => Err("an unverified case must be a mode-mismatch and say why".into()),
            };
        }
        let outcome = if case["kind"] == "sign-request" {
            let request = &case["request"];
            sign_request(
                &Key::from_seed(&from_hex(case["seed_hex"].as_str().unwrap())).unwrap(),
                request["method"].as_str().unwrap(),
                request["url"].as_str().unwrap(),
                &headers_of(request),
                &SignOptions {
                    body: body_of(request),
                    covered: Some(strings(&case["covered"])),
                    keyid: case["keyid"].as_str().map(str::to_string),
                    minimum: Some(strings(&data["policy"]["request_minimum"])),
                    ..Default::default()
                },
            )
            .map(|_| ())
        } else {
            run(case, &data).map(|_| ())
        };
        match outcome {
            Ok(()) => Err(format!("accepted; expected {expected}")),
            Err(e) if code(e.kind) == Some(expected) => Ok(()),
            Err(e) => Err(format!(
                "{} ({}): {e}; expected {expected}",
                e.kind,
                code(e.kind).unwrap_or("no code")
            )),
        }
    });
}

// --- legacy material, which fiki carries and never verifies ---

#[test]
fn legacy_vectors_carry_what_a_legacy_verifier_needs_and_their_provenance() {
    each(&load("legacy.json")["cases"], |case| {
        let source = &case["source"];
        let repo = source["repo"].as_str().unwrap_or("");
        if !["WebOfTrust/keria", "WebOfTrust/signify-ts"].contains(&repo) {
            return Err(format!("repo {repo}"));
        }
        if source["commit"].as_str().map(str::len) != Some(40) {
            return Err("commit".into());
        }
        for field in ["file", "lines"] {
            if !source[field].as_str().is_some_and(|s| !s.is_empty()) {
                return Err(format!("source.{field}"));
            }
        }
        for field in [
            "kind", "method", "path", "headers", "key", "keyid", "created",
        ] {
            if case.get(field).is_none() {
                return Err(format!("missing {field}"));
            }
        }
        let headers = headers_of(case);
        if !headers["Signature-Input"].starts_with("signify=") {
            return Err("Signature-Input".into());
        }
        if !headers["Signature"].starts_with("indexed=\"?0\";signify=\"0B") {
            return Err("Signature".into());
        }
        Ok(())
    });
}

#[test]
fn each_legacy_signature_verifies_over_its_stated_base() {
    // Transcription check only: pure Ed25519 over the base the file states, no legacy logic.
    each(&load("legacy.json")["cases"], |case| {
        let header = case["headers"]["Signature"].as_str().unwrap();
        let signature = header
            .split_once("signify=\"")
            .unwrap()
            .1
            .trim_end_matches('"');
        let raw_signature: [u8; 64] = b64_decode(&format!("AA{}", &signature[2..]), URL).unwrap()
            [2..]
            .try_into()
            .unwrap();
        let key = case["key"].as_str().unwrap();
        let raw_key: [u8; 32] = b64_decode(&format!("A{}", &key[1..]), URL).unwrap()[1..]
            .try_into()
            .unwrap();
        VerifyingKey::from_bytes(&raw_key)
            .unwrap()
            .verify(
                case["base"].as_str().unwrap().as_bytes(),
                &Signature::from_bytes(&raw_signature),
            )
            .map_err(|e| e.to_string())
    });
}

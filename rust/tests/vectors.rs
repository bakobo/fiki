//! The shared conformance vectors (`this.i` @5gf6r08f, @2tt6fmc0).
//!
//! They live at the repository root rather than under rust/ so this implementation and the other
//! four are held to the same bytes. A copy under each language is the drift the polyglot layout
//! exists to prevent, which is why this file reaches up two directories rather than embedding
//! anything.

use std::collections::BTreeMap;
use std::fs;

use fiki::{signature_base, verify_request, verifying_key, Key, SignatureParams, VerifyOptions};
use serde::Deserialize;

fn load<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = format!("{}/../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("the shared vectors are not where every port reaches them: {e}")
    });
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Deserialize)]
struct File<T> {
    cases: Vec<T>,
}

#[derive(Deserialize)]
struct AidCase {
    id: String,
    seed_hex: String,
    public_key_hex: String,
    aid: String,
    keyid: String,
}

#[derive(Deserialize)]
struct BaseCase {
    id: String,
    seed_hex: String,
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    covered: Vec<String>,
    created: i64,
    keyid: String,
    alg: Option<String>,
    base: String,
    signature: String,
}

#[derive(Deserialize)]
struct RequestCase {
    id: String,
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: Option<String>,
    max_age: Option<i64>,
    now: Option<i64>,
    #[serde(default)]
    aid: String,
    #[serde(default)]
    covered: Vec<String>,
    #[serde(default)]
    error: String,
}

impl RequestCase {
    fn options(&self) -> VerifyOptions {
        VerifyOptions {
            max_age: self.max_age,
            body: self.body.as_ref().map(|b| b.as_bytes().to_vec()),
            now: self.now,
            ..Default::default()
        }
    }
}

#[test]
fn aid_lens() {
    let file: File<AidCase> = load("aid-lens.json");
    for case in file.cases {
        let key = Key::from_seed(&from_hex(&case.seed_hex)).unwrap();
        assert_eq!(key.aid(), case.aid, "{}", case.id);
        assert_eq!(key.keyid(), case.keyid, "{}", case.id);
        let public = verifying_key(&case.aid).unwrap();
        assert_eq!(
            to_hex(public.as_bytes()),
            case.public_key_hex,
            "{}",
            case.id
        );
    }
}

#[test]
fn signature_bases_and_signatures() {
    let file: File<BaseCase> = load("signature-base.json");
    for case in file.cases {
        let params = SignatureParams {
            created: Some(case.created),
            keyid: Some(case.keyid.clone()),
            alg: case.alg.clone(),
            ..Default::default()
        };
        let base = signature_base(
            &case.method,
            &case.url,
            &case.headers,
            &case.covered,
            &params,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(base.clone()).unwrap(),
            case.base,
            "{}",
            case.id
        );
        // Ed25519 is deterministic, so a port that builds the right base produces the right bytes:
        // byte equality, not a verification round trip.
        let key = Key::from_seed(&from_hex(&case.seed_hex)).unwrap();
        let signature = fiki::Key::sign(&key, &base);
        let encoded = base64_std(&signature);
        assert_eq!(encoded, case.signature, "{}", case.id);
    }
}

fn base64_std(raw: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in raw.chunks(3) {
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
}

#[test]
fn accepts() {
    let file: File<RequestCase> = load("accepts.json");
    for case in file.cases {
        let verdict = verify_request(&case.method, &case.url, &case.headers, &case.options())
            .unwrap_or_else(|e| panic!("{} should verify: {e}", case.id));
        assert_eq!(verdict.aid, case.aid, "{}", case.id);
        assert_eq!(verdict.covered, case.covered, "{}", case.id);
    }
}

#[test]
fn refusals() {
    let file: File<RequestCase> = load("refusals.json");
    for case in file.cases {
        // Every entry names the kind fiki reports, so this port maps its own onto the same
        // condition rather than inventing a taxonomy of its own.
        let err = verify_request(&case.method, &case.url, &case.headers, &case.options())
            .expect_err(&format!("{} should be refused", case.id));
        assert_eq!(err.kind.to_string(), case.error, "{}", case.id);
    }
}

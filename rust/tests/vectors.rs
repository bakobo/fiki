//! The shared conformance vectors (`this.i` @5gf6r08f, @2tt6fmc0).
//!
//! They live at the repository root rather than under rust/ so this implementation and the other
//! four are held to the same bytes. A copy under each language is the drift the polyglot layout
//! exists to prevent, which is why this file reaches up two directories rather than embedding
//! anything.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use fiki::{
    signature_base, verify_request, verifying_key, Authorities, Key, Kind, Minimum,
    SignatureParams, Verdict, VerifyOptions, VECTORS_FORMAT,
};
use serde::Deserialize;
use serde_json::Value;

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
#[serde(deny_unknown_fields)]
struct RequestCase {
    id: String,
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: Option<String>,
    max_age: Option<i64>,
    now: Option<i64>,
    /// "default" leaves the minimum unstated, null is the explicit opt-out, a list is that minimum
    /// (format 3, `this.i` @524c8qgv).
    minimum: Value,
    /// null declines the check, a list is the hosts served. Anything else is a shape this port's
    /// types cannot express, which only misuse.json carries.
    authorities: Value,
    expected_aid: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
    #[serde(default)]
    aid: String,
    /// The keyid as it arrived, which format 2 pins on every accept case (`this.i` @5zrf8gjk).
    #[serde(default)]
    keyid: Option<String>,
    #[serde(default)]
    covered: Vec<String>,
    #[serde(default)]
    error: String,
    /// The policy fields a misuse case leaves out of the call altogether.
    #[serde(default)]
    omit: Vec<String>,
}

/// Every field a verify case carries is required, so a vector that drops one fails here rather than
/// being read as a default; one this driver does not know fails through `deny_unknown_fields`
/// (review V-M8).
const REQUIRED: [&str; 10] = [
    "id",
    "method",
    "url",
    "headers",
    "body",
    "max_age",
    "now",
    "minimum",
    "authorities",
    "expected_aid",
];

fn verify_cases(name: &str) -> Vec<RequestCase> {
    let file: File<Value> = load(name);
    assert!(file.cases.len() > 5, "{name} has almost no cases");
    file.cases
        .into_iter()
        .map(|raw| {
            for field in REQUIRED {
                assert!(
                    raw.get(field).is_some(),
                    "{name}: a case without {field}: {raw}"
                );
            }
            serde_json::from_value(raw.clone()).unwrap_or_else(|e| panic!("{name}: {e}: {raw}"))
        })
        .collect()
}

impl RequestCase {
    /// The verifier's stated policy, or `Err` when the case's `authorities` is a shape
    /// `Authorities` cannot hold, such as a bare string or a list holding a number.
    fn options(&self) -> Result<VerifyOptions, String> {
        let omitted = |field: &str| self.omit.iter().any(|f| f == field);
        for field in &self.omit {
            if !["minimum", "authorities", "expected_aid"].contains(&field.as_str()) {
                return Err(format!(
                    "omit names {field:?}, which this driver does not know"
                ));
            }
        }
        let minimum = match &self.minimum {
            _ if omitted("minimum") => Minimum::Default,
            Value::String(s) if s == "default" => Minimum::Default,
            Value::Null => Minimum::Off,
            list => Minimum::Of(
                serde_json::from_value(list.clone()).map_err(|e| format!("minimum: {e}"))?,
            ),
        };
        let authorities = match &self.authorities {
            _ if omitted("authorities") => Authorities::Unstated,
            Value::Null => Authorities::Unchecked,
            hosts => Authorities::Served(
                serde_json::from_value::<BTreeSet<String>>(hosts.clone())
                    .map_err(|e| format!("authorities {hosts} is not a set of hosts: {e}"))?,
            ),
        };
        Ok(VerifyOptions {
            max_age: self.max_age,
            body: self.body.as_ref().map(|b| b.as_bytes().to_vec()),
            now: self.now,
            minimum,
            authorities,
            expected_aid: if omitted("expected_aid") {
                None
            } else {
                self.expected_aid.clone()
            },
            ..Default::default()
        })
    }

    fn verify(&self) -> Result<Result<Verdict, fiki::Error>, String> {
        Ok(verify_request(
            &self.method,
            &self.url,
            &self.headers,
            &self.options()?,
        ))
    }
}

#[derive(Deserialize)]
struct FormatHeader {
    vectors_format: u32,
}

#[test]
fn this_port_satisfies_the_vectors_format_it_is_running() {
    // A port running newer vectors fails here rather than passing a subset and reporting
    // conformance it no longer has: the cases it never implemented would simply not be in the file
    // it last read.
    for name in [
        "aid-lens.json",
        "signature-base.json",
        "accepts.json",
        "refusals.json",
        "misuse.json",
    ] {
        let header: FormatHeader = load(name);
        assert_eq!(header.vectors_format, VECTORS_FORMAT, "{name}");
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
    each(
        file.cases,
        |c| c.id.clone(),
        |case| {
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
            .map_err(|e| format!("{}: {e}", e.kind))?;
            let text = String::from_utf8(base.clone()).unwrap();
            if text != case.base {
                return Err(format!("base {text:?}"));
            }
            // Ed25519 is deterministic, so a port that builds the right base produces the right bytes:
            // byte equality, not a verification round trip.
            let key = Key::from_seed(&from_hex(&case.seed_hex)).unwrap();
            let encoded = base64_std(&key.sign(&base));
            if encoded != case.signature {
                return Err(format!("signature {encoded}"));
            }
            Ok(())
        },
    );
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

/// Runs every case and reports all the failures together, so one red run names every case that is
/// wrong rather than only the first.
fn each<T>(cases: Vec<T>, id: impl Fn(&T) -> String, check: impl Fn(&T) -> Result<(), String>) {
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| check(case).err().map(|why| format!("{}: {why}", id(case))))
        .collect();
    assert!(
        failures.is_empty(),
        "{} case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn accepts() {
    each(
        verify_cases("accepts.json"),
        |c| c.id.clone(),
        |case| {
            let verdict = case
                .verify()?
                .map_err(|e| format!("should verify: {}: {e}", e.kind))?;
            if verdict.aid != case.aid {
                return Err(format!("aid {}", verdict.aid));
            }
            // Format 2 (@5zrf8gjk): the keyid exactly as it arrived, beside the identity that vouched.
            if case.keyid.is_none() || verdict.keyid != case.keyid {
                return Err(format!("keyid {:?}", verdict.keyid));
            }
            if verdict.covered != case.covered {
                return Err(format!("covered {:?}", verdict.covered));
            }
            Ok(())
        },
    );
}

#[test]
fn refusals() {
    // Every entry names the kind fiki reports, so this port maps its own onto the same condition
    // rather than inventing a taxonomy of its own.
    each(
        verify_cases("refusals.json"),
        |c| c.id.clone(),
        |case| match case.verify()? {
            Ok(_) => Err(format!("accepted; expected {}", case.error)),
            Err(e) if e.kind.to_string() == case.error => Ok(()),
            Err(e) => Err(format!("{}: {e}; expected {}", e.kind, case.error)),
        },
    );
}

#[test]
fn misuse() {
    // A mistake in the call is InvalidArgument, never one of the kinds a message earns
    // (`this.i` @5zrf8gjk). Two of these cases, a bare string and a list holding a number, are
    // mistakes Rust's types refuse before the program runs: `Authorities` holds a set of
    // `String`s and `Authorities::served` takes no `&str`. For those the driver asserts that the
    // vector's value cannot become an `Authorities` at all, which is this port's form of the
    // refusal.
    each(
        verify_cases("misuse.json"),
        |c| c.id.clone(),
        |case| {
            if case.error != "caller" {
                return Err(format!("error {:?}, expected \"caller\"", case.error));
            }
            let options = match case.options() {
                Ok(options) => options,
                Err(why) if why.starts_with("authorities ") => return Ok(()),
                Err(why) => return Err(why),
            };
            match verify_request(&case.method, &case.url, &case.headers, &options) {
                Ok(_) => Err("accepted; expected InvalidArgument".into()),
                Err(e) if e.kind == Kind::InvalidArgument => Ok(()),
                Err(e) => Err(format!("{}: {e}; expected InvalidArgument", e.kind)),
            }
        },
    );
}

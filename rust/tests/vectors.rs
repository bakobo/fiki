//! The shared conformance vectors (`this.i` @5gf6r08f, @2tt6fmc0).
//!
//! They live at the repository root rather than under rust/ so this implementation and the other
//! four are held to the same bytes. A copy under each language is the drift the polyglot layout
//! exists to prevent, which is why this file reaches up two directories rather than embedding
//! anything.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use fiki::{
    sign_request, sign_response, signature_base, verify_request, verify_response, verifying_key,
    Authorities, ExpectedKeyid, Key, Kind, Minimum, Request, SignOptions, SignatureParams, Verdict,
    VerifyOptions, VECTORS_FORMAT,
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

/// The raw cases of a file, which must hold at least five.
fn raw_cases(name: &str) -> Vec<Value> {
    let file: File<Value> = load(name);
    assert!(file.cases.len() >= 5, "{name} has almost no cases");
    file.cases
}

/// One case read into `T`, once every field in `required` is present: a vector that drops one
/// fails here rather than being read as a default, and one the driver does not know fails through
/// `deny_unknown_fields` (review V-M8).
fn typed_case<T: for<'de> Deserialize<'de>>(name: &str, raw: &Value, required: &[&str]) -> T {
    for field in required {
        assert!(
            raw.get(field).is_some(),
            "{name}: a case without {field}: {}",
            clip(raw)
        );
    }
    serde_json::from_value(raw.clone()).unwrap_or_else(|e| panic!("{name}: {e}: {}", clip(raw)))
}

/// A case as a panic message may show it: some of them hold 9000-byte values.
fn clip(raw: &Value) -> String {
    raw.to_string().chars().take(600).collect()
}

fn verify_cases(name: &str) -> Vec<RequestCase> {
    raw_cases(name)
        .iter()
        .map(|raw| typed_case(name, raw, &REQUIRED))
        .collect()
}

/// Every refusal's message holds no control character and is at most 1024 characters, so an
/// untrusted value is quoted escaped and cut (`this.i` @524c8qgv, part-two refinements). py's
/// `_well_formed` is the reference.
fn well_formed(error: &fiki::Error) -> Result<(), String> {
    let message = error.to_string();
    let length = message.chars().count();
    if length > 1024 {
        return Err(format!("its message is {length} characters"));
    }
    if message.chars().any(|c| c < ' ' || c == '\x7f') {
        return Err(format!(
            "its message holds a control character: {:?}",
            message.chars().take(200).collect::<String>()
        ));
    }
    Ok(())
}

/// A request as the vectors write one, for a response to answer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestJson {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: Option<String>,
}

impl RequestJson {
    fn request(&self) -> Request {
        Request {
            method: self.method.clone(),
            url: self.url.clone(),
            headers: self.headers.clone(),
            body: self.body.as_ref().map(|b| b.as_bytes().to_vec()),
        }
    }
}

/// A `verify_response` case: `responses.json`, and `misuse.json`'s `kind: response` cases.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseCase {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    kind: Option<String>,
    status: u16,
    headers: BTreeMap<String, String>,
    body: Option<String>,
    request: Option<RequestJson>,
    /// "default" leaves the minimum unstated, null is the explicit opt-out, a list is that minimum.
    minimum: Value,
    /// null is the explicit decline, a string the AID expected (format 3 part two, @524c8qgv).
    expected_keyid: Option<String>,
    max_age: Option<i64>,
    now: Option<i64>,
    // A misuse case carries the request line of the request it answers beside it, unread.
    #[serde(default)]
    #[allow(dead_code)]
    method: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    url: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
    #[serde(default)]
    keyid: Option<String>,
    #[serde(default)]
    covered: Vec<String>,
    #[serde(default)]
    error: String,
    #[serde(default)]
    omit: Vec<String>,
}

const RESPONSE_REQUIRED: [&str; 9] = [
    "id",
    "status",
    "headers",
    "body",
    "request",
    "minimum",
    "expected_keyid",
    "max_age",
    "now",
];

impl ResponseCase {
    fn options(&self) -> Result<VerifyOptions, String> {
        let omitted = |field: &str| self.omit.iter().any(|f| f == field);
        for field in &self.omit {
            if !["minimum", "expected_keyid"].contains(&field.as_str()) {
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
        let expected_keyid = match &self.expected_keyid {
            _ if omitted("expected_keyid") => ExpectedKeyid::Unstated,
            None => ExpectedKeyid::Unchecked,
            Some(aid) => ExpectedKeyid::Is(aid.clone()),
        };
        Ok(VerifyOptions {
            max_age: self.max_age,
            body: self.body.as_ref().map(|b| b.as_bytes().to_vec()),
            now: self.now,
            minimum,
            expected_keyid,
            ..Default::default()
        })
    }

    fn verify(&self) -> Result<Result<Verdict, fiki::Error>, String> {
        let request = self.request.as_ref().map(RequestJson::request);
        Ok(verify_response(
            self.status,
            &self.headers,
            request.as_ref(),
            &self.options()?,
        ))
    }
}

/// A `signs.json` case: what a signer emits, byte for byte (review V-C4).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignCase {
    id: String,
    kind: String,
    seed_hex: String,
    method: Option<String>,
    url: Option<String>,
    headers: BTreeMap<String, String>,
    body: Option<String>,
    /// null takes the signer's default set.
    covered: Option<Vec<String>>,
    created: Option<i64>,
    expires: Option<i64>,
    nonce: Option<String>,
    tag: Option<String>,
    minimum: Option<Vec<String>>,
    status: Option<u16>,
    request: Option<RequestJson>,
    #[serde(default)]
    keyid: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    expected_headers: Option<BTreeMap<String, String>>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

const SIGN_REQUIRED: [&str; 16] = [
    "id", "kind", "seed_hex", "method", "url", "headers", "body", "covered", "created", "expires",
    "nonce", "tag", "minimum", "status", "request", "label",
];

impl SignCase {
    fn sign(&self) -> Result<fiki::Result<BTreeMap<String, String>>, String> {
        let key = Key::from_seed(&from_hex(&self.seed_hex)).unwrap();
        let opts = SignOptions {
            body: self.body.as_ref().map(|b| b.as_bytes().to_vec()),
            covered: self.covered.clone(),
            created: self.created,
            expires: self.expires,
            nonce: self.nonce.clone(),
            tag: self.tag.clone(),
            minimum: self.minimum.clone(),
            keyid: self.keyid.clone(),
            label: self.label.clone(),
        };
        match self.kind.as_str() {
            "request" => Ok(sign_request(
                &key,
                self.method
                    .as_deref()
                    .ok_or("a request case with no method")?,
                self.url.as_deref().ok_or("a request case with no url")?,
                &self.headers,
                &opts,
            )),
            "response" => {
                let request = self.request.as_ref().map(RequestJson::request);
                Ok(sign_response(
                    &key,
                    self.status.ok_or("a response case with no status")?,
                    request.as_ref(),
                    &self.headers,
                    &opts,
                ))
            }
            other => Err(format!("kind {other:?}, which this driver does not know")),
        }
    }
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
        "signs.json",
        "responses.json",
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
            Err(e) if e.kind.to_string() == case.error => well_formed(&e),
            Err(e) => Err(format!("{}: {e}; expected {}", e.kind, case.error)),
        },
    );
}

#[test]
fn responses() {
    // verify_response's own policy (format 3 part two, `this.i` @524c8qgv): RESPONSE_MINIMUM by
    // default, and expected_keyid stated.
    let cases: Vec<ResponseCase> = raw_cases("responses.json")
        .iter()
        .map(|raw| typed_case("responses.json", raw, &RESPONSE_REQUIRED))
        .collect();
    each(
        cases,
        |c| c.id.clone(),
        |case| match (case.verify()?, case.error.as_str()) {
            (Ok(verdict), "") => {
                if case.keyid.is_none() || verdict.keyid != case.keyid {
                    return Err(format!("keyid {:?}", verdict.keyid));
                }
                if verdict.covered != case.covered {
                    return Err(format!("covered {:?}", verdict.covered));
                }
                Ok(())
            }
            (Ok(_), error) => Err(format!("accepted; expected {error}")),
            (Err(e), "") => Err(format!("should verify: {}: {e}", e.kind)),
            (Err(e), error) if e.kind.to_string() == error => well_formed(&e),
            (Err(e), error) => Err(format!("{}: {e}; expected {error}", e.kind)),
        },
    );
}

#[test]
fn signs() {
    // What the signer emits, byte for byte (review V-C4): no shared vector called a signer before
    // format 3, so a port whose default covered set dropped @query passed everything.
    let cases: Vec<SignCase> = raw_cases("signs.json")
        .iter()
        .map(|raw| typed_case("signs.json", raw, &SIGN_REQUIRED))
        .collect();
    each(
        cases,
        |c| c.id.clone(),
        |case| match (case.sign()?, case.error.as_deref()) {
            (Ok(headers), None) => match &case.expected_headers {
                Some(expected) if &headers == expected => Ok(()),
                Some(_) => Err(format!("headers {headers:?}")),
                None => Err("a case with neither an error nor expected_headers".into()),
            },
            (Ok(_), Some(error)) => Err(format!("signed; expected {error}")),
            (Err(e), None) => Err(format!("should sign: {}: {e}", e.kind)),
            // A mistake in the call is InvalidArgument, never a kind a message earns (@5zrf8gjk).
            (Err(e), Some("caller")) if e.kind == Kind::InvalidArgument => Ok(()),
            (Err(e), Some(error)) if e.kind.to_string() == error => well_formed(&e),
            (Err(e), Some(error)) => Err(format!("{}: {e}; expected {error}", e.kind)),
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
    let raw = raw_cases("misuse.json");
    let (responses, requests): (Vec<&Value>, Vec<&Value>) =
        raw.iter().partition(|c| c["kind"] == "response");
    let responses: Vec<ResponseCase> = responses
        .into_iter()
        .map(|raw| typed_case("misuse.json", raw, &RESPONSE_REQUIRED))
        .collect();
    assert!(!responses.is_empty(), "misuse.json has no response case");
    each(
        responses,
        |c| c.id.clone(),
        |case| {
            if case.error != "caller" {
                return Err(format!("error {:?}, expected \"caller\"", case.error));
            }
            match case.verify()? {
                Ok(_) => Err("accepted; expected InvalidArgument".into()),
                Err(e) if e.kind == Kind::InvalidArgument => Ok(()),
                Err(e) => Err(format!("{}: {e}; expected InvalidArgument", e.kind)),
            }
        },
    );
    each(
        requests
            .into_iter()
            .map(|raw| typed_case::<RequestCase>("misuse.json", raw, &REQUIRED))
            .collect(),
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

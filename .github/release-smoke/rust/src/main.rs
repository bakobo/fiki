//! Release smoke test for the fiki crate. The same four checks as every port's smoke test
//! (docs/releasing.md): a plain vector, a plain round trip, a KERI vector through a resolver, and
//! a KERI round trip under a caller-chosen AID keyid. Usage: cargo run -- <vectors-dir>
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use fiki::{
    sign_request, verify_request, Authorities, Key, MaxAge, Minimum, Resolver, SignOptions,
    VerifyOptions, REQUEST_MINIMUM,
};
use serde_json::Value;

fn load(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).expect("read vector file"))
        .expect("parse vector file")
}

fn headers(value: &Value) -> BTreeMap<String, String> {
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect()
}

fn check(name: &str, got: &str, want: &str) {
    if got != want {
        eprintln!("FAIL {name}: got {got:?}, want {want:?}");
        std::process::exit(1);
    }
    println!("ok   {name}");
}

fn case<'a>(file: &'a Value, id: &str) -> &'a Value {
    file["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .expect("named case is present")
}

fn main() {
    let vectors = std::env::args()
        .nth(1)
        .expect("usage: fiki-release-smoke <vectors-dir>");
    let vectors = Path::new(&vectors);
    let signing_minimum: Vec<String> = REQUEST_MINIMUM.map(String::from).to_vec();

    let accepts = load(&vectors.join("accepts.json"));
    let plain = case(&accepts, "default-covered-get");
    let verdict = verify_request(
        plain["method"].as_str().unwrap(),
        plain["url"].as_str().unwrap(),
        &headers(&plain["headers"]),
        // The vector's null max_age and null authorities are the explicit declines; its minimum is
        // the default.
        &VerifyOptions {
            max_age: MaxAge::Unchecked,
            authorities: Authorities::Unchecked,
            now: plain["now"].as_i64(),
            ..Default::default()
        },
    )
    .expect("plain vector verifies");
    check("plain vector", &verdict.aid, plain["aid"].as_str().unwrap());

    let seed: Vec<u8> = (0u8..32).collect();
    let key = Key::from_seed(&seed).unwrap();
    let (url, body) = (
        "https://api.example.com/things?limit=1",
        b"{\"hello\": \"world\"}".to_vec(),
    );
    let signed = sign_request(
        &key,
        "POST",
        url,
        &BTreeMap::new(),
        &SignOptions {
            body: Some(body.clone()),
            ..Default::default()
        },
    )
    .expect("plain signs");
    let verdict = verify_request(
        "POST",
        url,
        &signed,
        &VerifyOptions {
            max_age: MaxAge::seconds(300),
            body: Some(body),
            expected_aid: Some(key.aid()),
            authorities: Authorities::served(["api.example.com"]),
            ..Default::default()
        },
    )
    .expect("plain round trip verifies");
    check("plain round trip", &verdict.aid, &key.aid());

    let keri = load(&vectors.join("keri").join("requests.json"));
    let table: HashMap<String, Value> = keri["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| (k["keyid"].as_str().unwrap().to_string(), k.clone()))
        .collect();
    let lookup = table.clone();
    let resolve: Resolver = Arc::new(move |keyid: &str| {
        Ok(lookup
            .get(keyid)
            .and_then(|k| k["effective_key"].as_str())
            .map(|text| {
                let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(text)
                    .unwrap();
                <[u8; 32]>::try_from(raw.as_slice()).unwrap()
            }))
    });
    let kase = case(&keri, "get-with-query");
    let request = &kase["request"];
    let verdict = verify_request(
        request["method"].as_str().unwrap(),
        request["url"].as_str().unwrap(),
        &headers(&request["headers"]),
        &VerifyOptions {
            max_age: MaxAge::seconds(keri["policy"]["max_age"].as_i64().unwrap()),
            skew: keri["policy"]["skew"].as_i64(),
            now: kase["now"].as_i64(),
            resolve: Some(resolve.clone()),
            minimum: Minimum::of(REQUEST_MINIMUM),
            authorities: Authorities::Unchecked,
            ..Default::default()
        },
    )
    .expect("KERI vector verifies");
    let keyid = kase["expected"]["keyid"].as_str().unwrap();
    check("KERI vector", &verdict.aid, keyid);

    let signer =
        Key::from_seed(&hex::decode(table[keyid]["seed_hex"].as_str().unwrap()).unwrap()).unwrap();
    let url = "https://keria.example.com/identifiers?type=rot";
    let signed = sign_request(
        &signer,
        "GET",
        url,
        &BTreeMap::new(),
        &SignOptions {
            keyid: Some(keyid.to_string()),
            minimum: Some(signing_minimum),
            ..Default::default()
        },
    )
    .expect("KERI signs");
    let verdict = verify_request(
        "GET",
        url,
        &signed,
        &VerifyOptions {
            max_age: MaxAge::seconds(300),
            resolve: Some(resolve),
            minimum: Minimum::of(REQUEST_MINIMUM),
            authorities: Authorities::served(["keria.example.com"]),
            ..Default::default()
        },
    )
    .expect("KERI round trip verifies");
    check("KERI round trip", &verdict.aid, keyid);
}

//! The Rust port's answers to differential/cases.json, as a map from case id to outcome.
//!
//! `cargo run --release -- [cases.json] [out.json]` from differential/rust. The outcome spelling
//! is shared by all six runners and described in differential/README.md.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use fiki::{verify_request, Authorities, Kind, MaxAge, Minimum, VerifyOptions};
use serde_json::Value;

/// How much of a caller error's message an outcome carries; the same in every runner.
const PREFIX: usize = 40;

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("a list of strings")
        .iter()
        .map(|item| item.as_str().expect("a string").to_string())
        .collect()
}

/// The case's stated policy in Rust's spelling: a null max_age is `MaxAge::Unchecked`, null
/// authorities `Authorities::Unchecked`, a null minimum `Minimum::Off`, "default" `Minimum::Default`.
fn options(c: &Value) -> VerifyOptions {
    VerifyOptions {
        max_age: c["max_age"]
            .as_i64()
            .map_or(MaxAge::Unchecked, MaxAge::Seconds),
        body: c["body"].as_str().map(|b| b.as_bytes().to_vec()),
        now: Some(c["now"].as_i64().expect("now is stated")),
        expected_aid: c["expected_aid"].as_str().map(str::to_string),
        authorities: match &c["authorities"] {
            Value::Null => Authorities::Unchecked,
            hosts => Authorities::Served(strings(hosts).into_iter().collect::<BTreeSet<_>>()),
        },
        minimum: match &c["minimum"] {
            Value::String(s) if s == "default" => Minimum::Default,
            Value::Null => Minimum::Off,
            list => Minimum::Of(strings(list)),
        },
        ..Default::default()
    }
}

fn outcome(c: &Value) -> String {
    let headers: BTreeMap<String, String> = c["headers"]
        .as_object()
        .expect("headers")
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().expect("a header value").to_string()))
        .collect();
    let opts = options(c);
    let method = c["method"].as_str().expect("method");
    let url = c["url"].as_str().expect("url");
    match catch_unwind(AssertUnwindSafe(|| {
        verify_request(method, url, &headers, &opts)
    })) {
        Err(_) => "crash:panic".to_string(),
        Ok(Ok(verdict)) => format!("ok:{}", verdict.aid),
        // A mistake in the call is InvalidArgument and no other kind (@5zrf8gjk).
        Ok(Err(e)) if e.kind == Kind::InvalidArgument => {
            format!(
                "caller:{}",
                e.message.chars().take(PREFIX).collect::<String>()
            )
        }
        Ok(Err(e)) => e.kind.to_string(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cases_path = args.get(1).map_or("../cases.json", String::as_str);
    let out_path = args.get(2).map_or("../out/rust.json", String::as_str);
    let raw = std::fs::read_to_string(cases_path).expect("cases.json is readable");
    let file: Value = serde_json::from_str(&raw).expect("cases.json is JSON");
    let cases = file["cases"].as_array().expect("a cases array");
    // A panic is recorded as an outcome, so the default hook's backtrace on stderr is noise.
    std::panic::set_hook(Box::new(|_| {}));
    let start = Instant::now();
    let out: BTreeMap<String, String> = cases
        .iter()
        .map(|c| (c["id"].as_str().expect("id").to_string(), outcome(c)))
        .collect();
    let _ = std::panic::take_hook();
    if let Some(parent) = std::path::Path::new(out_path).parent() {
        std::fs::create_dir_all(parent).expect("the output directory");
    }
    let encoded = serde_json::to_string(&out).expect("an outcome map");
    std::fs::write(out_path, encoded + "\n").expect("the outcome map is writable");
    println!(
        "rust: {} cases in {:.1}s",
        out.len(),
        start.elapsed().as_secs_f64()
    );
}

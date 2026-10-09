//! A deterministic, seeded mutation test of the RFC 8941 parser and `verify_request` (tick 7xbw).
//!
//! In the crate rather than under tests/, because the parser is internal. No dependency: the
//! generator is a hand-written xorshift, and a fixed seed makes every run the same run, so a
//! failure prints the iteration and the input, and reproduces.
//!
//! Mutants are made at the level of bytes and then decoded lossily, because a Rust `&str` cannot
//! hold invalid UTF-8: a mutant that is not UTF-8 still reaches the API, as the replacement
//! characters the decoder writes, rather than being dropped. The mutation alphabet carries
//! non-ASCII text, the C1 controls U+0080 and U+009F, U+2028, and bytes that are not UTF-8 alone.
//!
//! Allowed outcomes. From the parser, a value or its `SyntaxError`, which its types already
//! guarantee, so what this checks there is that nothing panics. From `verify_request`, a verdict
//! or a refusal of some kind other than `InvalidArgument`: wire input is never the caller's
//! mistake, and `this.i` @2n99rej7 names no path by which it reaches `InvalidArgument` there.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use serde_json::Value as Json;

use crate::errors::Kind;
use crate::sfv::{parse_dictionary, parse_item, parse_list};
use crate::{
    verify_request, Authorities, ExpectedKeyid, MaxAge, Minimum, VerifyOptions, DEFAULT_MINIMUM,
};

const SEED: u64 = 0x0942_1894_1000_7cb0;
const ITERATIONS: usize = 25_000;

/// What a mutation may insert: RFC 8941's punctuation, digits and letters, and text the grammar
/// refuses, some of it not UTF-8 on its own.
const ALPHABET: &[&[u8]] = &[
    b"\"",
    b"(",
    b")",
    b",",
    b";",
    b"=",
    b":",
    b"*",
    b"?",
    b"-",
    b".",
    b"\\",
    b" ",
    b"\t",
    b"0",
    b"1",
    b"9",
    b"a",
    b"z",
    b"A",
    b"@",
    b"%",
    b"/",
    b"+",
    b"\r\n",
    b"\0",
    b"\x7f",
    // é, U+0080, U+009F, U+2028, U+2029
    b"\xc3\xa9",
    b"\xc2\x80",
    b"\xc2\x9f",
    b"\xe2\x80\xa8",
    b"\xe2\x80\xa9",
    // A lone continuation byte, a lead byte with nothing after it, and a byte UTF-8 never uses.
    b"\x80",
    b"\xc3",
    b"\xff",
];

/// xorshift64*, which is enough to spread mutations and needs no crate.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors")
}

fn json(path: PathBuf) -> Json {
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

/// The inputs mutants are made from: every corpus case's combined raw value, and the
/// Signature-Input and Signature values of the shared accept and refusal vectors.
fn seeds() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let corpus = vectors().join("third_party/structured-field-tests");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&corpus)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    for file in files {
        for case in json(file).as_array().unwrap() {
            let raw: Vec<&str> = case["raw"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_str().unwrap())
                .collect();
            out.push(raw.join(", ").into_bytes());
        }
    }
    for name in ["accepts.json", "refusals.json"] {
        for case in json(vectors().join(name))["cases"].as_array().unwrap() {
            for header in ["Signature-Input", "Signature"] {
                if let Some(value) = case["headers"][header].as_str() {
                    out.push(value.as_bytes().to_vec());
                }
            }
        }
    }
    out
}

/// One to four byte-level mutations of a seed: a bit flipped, a piece of the alphabet inserted, a
/// run deleted, the tail truncated, or a piece of another seed spliced in.
fn mutate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut out = seeds[rng.below(seeds.len())].clone();
    for _ in 0..=rng.below(4) {
        let at = rng.below(out.len() + 1);
        match rng.below(5) {
            0 if !out.is_empty() => {
                let at = at.min(out.len() - 1);
                out[at] ^= 1 << rng.below(8);
            }
            1 => {
                let piece = ALPHABET[rng.below(ALPHABET.len())];
                out.splice(at..at, piece.iter().copied());
            }
            2 => {
                let end = (at + 1 + rng.below(8)).min(out.len());
                out.drain(at.min(end)..end);
            }
            3 => out.truncate(at),
            _ => {
                let other = &seeds[rng.below(seeds.len())];
                let from = rng.below(other.len() + 1);
                let to = (from + rng.below(32)).min(other.len());
                let cut = (at + rng.below(32)).min(out.len());
                out.splice(at..cut, other[from..to].iter().copied());
            }
        }
    }
    out
}

/// The request every verify mutant is grafted onto: the first shared accept vector.
struct Base {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    now: i64,
}

fn base() -> Base {
    let file = json(vectors().join("accepts.json"));
    let case = &file["cases"][0];
    Base {
        method: case["method"].as_str().unwrap().into(),
        url: case["url"].as_str().unwrap().into(),
        headers: case["headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
            .collect(),
        now: case["now"].as_i64().unwrap(),
    }
}

/// Two policies, each with every decision stated: fiki's default minimum with a served authority
/// and an age limit, and the explicit opt-outs.
fn policies(now: i64) -> [VerifyOptions; 2] {
    [
        VerifyOptions {
            minimum: Minimum::of(DEFAULT_MINIMUM),
            authorities: Authorities::served(["api.example.com"]),
            expected_keyid: ExpectedKeyid::Unchecked,
            max_age: MaxAge::seconds(300),
            skew: Some(5),
            now: Some(now),
            ..Default::default()
        },
        VerifyOptions {
            minimum: Minimum::Off,
            authorities: Authorities::Unchecked,
            expected_keyid: ExpectedKeyid::Unchecked,
            max_age: MaxAge::Unchecked,
            now: Some(now),
            ..Default::default()
        },
    ]
}

/// What one mutant does that it must not, if anything.
fn misbehaviour(text: &str, header: &str, base: &Base, opts: &VerifyOptions) -> Option<String> {
    let parsed = catch_unwind(|| {
        let _ = parse_dictionary(text);
        let _ = parse_list(text);
        let _ = parse_item(text);
    });
    if parsed.is_err() {
        return Some("the parser panicked".into());
    }
    let mut headers = base.headers.clone();
    headers.insert(header.into(), text.into());
    match catch_unwind(AssertUnwindSafe(|| {
        verify_request(&base.method, &base.url, &headers, opts)
    })) {
        Err(_) => Some(format!("verify_request panicked, with {header} mutated")),
        Ok(Err(e)) if e.kind == Kind::InvalidArgument => Some(format!(
            "verify_request called wire input in {header} the caller's mistake: {}",
            e.message
        )),
        Ok(_) => None,
    }
}

#[test]
fn mutants_of_the_corpus_and_the_vectors_never_panic_or_blame_the_caller() {
    let seeds = seeds();
    assert!(seeds.len() > 1800, "{} seeds", seeds.len());
    let base = base();
    let policies = policies(base.now);
    let mut rng = Rng(SEED);
    let mut failures = Vec::new();
    for i in 0..ITERATIONS {
        let mutant = mutate(&mut rng, &seeds);
        let text = String::from_utf8_lossy(&mutant).into_owned();
        let header = ["Signature-Input", "Signature"][i % 2];
        if let Some(why) = misbehaviour(&text, header, &base, &policies[(i / 2) % 2]) {
            failures.push(format!(
                "seed {SEED:#x}, iteration {i}: {why}; input {text:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mutants misbehaved:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The mutator makes what it says it does, so the test above cannot pass by feeding nothing
/// interesting: within the fixed run, some mutants are not UTF-8, some carry a C1 control or
/// U+2028, and some get through parsing as far as the signature check.
#[test]
fn the_mutants_reach_what_they_are_meant_to() {
    let seeds = seeds();
    let base = base();
    let policies = policies(base.now);
    let mut rng = Rng(SEED);
    let (mut lossy, mut c1, mut separator) = (0, 0, 0);
    let mut kinds = std::collections::BTreeMap::new();
    for i in 0..ITERATIONS {
        let mutant = mutate(&mut rng, &seeds);
        lossy += usize::from(std::str::from_utf8(&mutant).is_err());
        let text = String::from_utf8_lossy(&mutant).into_owned();
        c1 += usize::from(text.chars().any(|c| ('\u{80}'..='\u{9f}').contains(&c)));
        separator += usize::from(text.contains('\u{2028}'));
        let mut headers = base.headers.clone();
        headers.insert(["Signature-Input", "Signature"][i % 2].into(), text);
        let opts = &policies[(i / 2) % 2];
        if let Err(e) = verify_request(&base.method, &base.url, &headers, opts) {
            *kinds.entry(e.kind).or_insert(0) += 1;
        }
    }
    assert!(
        lossy > 100
            && c1 > 100
            && separator > 50
            && kinds.get(&Kind::SignatureMismatch).is_some_and(|&n| n > 20)
            && kinds.len() >= 10,
        "not UTF-8 {lossy}, C1 {c1}, U+2028 {separator}, refusals {kinds:?}"
    );
}

//! The httpwg structured-field-tests corpus, vendored at vectors/third_party (`this.i` @7fexwu3s),
//! run against this port's RFC 8941 parser.
//!
//! In the crate rather than under tests/, because the parser is internal: nothing public reads a
//! bare structured field, and widening the API so a test could reach it would be the wrong trade.
//!
//! The corpus is written by RFC 8941's authors and is independent of fiki, so where this parser
//! disagrees with it the parser is wrong, except where a recorded fiki decision says otherwise.
//! Those exceptions are the only ones, and each is named below: RFC 9651's Dates and Display
//! Strings are refused (@7vdhfv3q), fiki's input bounds are refused (@5zrf8gjk), a byte sequence
//! whose padding is missing, partial or excessive is refused (@2g4xxev9), and the entry point
//! refuses a field that is empty after OWS (@2nyel5g0, pinned by vectors/refusals.json).
//!
//! Entry points. A dictionary case runs through `parse_bounded`, the bounded entry point
//! `verify_request` reads Signature-Input through, which checks `MAX_FIELD_BYTES` on the raw value
//! and then `MAX_DICTIONARY_MEMBERS`, `MAX_INNER_LIST_ITEMS` and `MAX_PARAMETERS` on what parsed. A
//! list or item case runs through `bounded_list` or `bounded_item` below, which apply the same
//! `check_size` and `check_counts` around the parser's list and item readers, a list's members
//! counted against `MAX_DICTIONARY_MEMBERS` as the other five ports count them.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value as Json;

use crate::errors::{Error, Kind};
use crate::messages::{check_counts, check_size, parse_bounded};
use crate::sfv::{parse_item, parse_list, Item, Member, Params, Value};
use crate::{
    sign_request, Key, SignOptions, MAX_DICTIONARY_MEMBERS, MAX_FIELD_BYTES, MAX_INNER_LIST_ITEMS,
    MAX_PARAMETERS,
};

const NAME: &str = "Signature-Input";
const KIND: Kind = Kind::MalformedSignatureInput;

/// Every file's case count, read once from the corpus at 00462dd when this test was written. A
/// corpus refresh that adds, drops or empties a file fails here rather than quietly changing what
/// is covered; no case in any file is skipped.
const CORPUS_COUNTS: [(&str, usize); 20] = [
    ("binary.json", 17),
    ("boolean.json", 12),
    ("date.json", 17),
    ("dictionary.json", 26),
    ("display-string.json", 22),
    ("examples.json", 21),
    ("item.json", 5),
    ("key-generated.json", 640),
    ("large-generated.json", 11),
    ("list.json", 11),
    ("listlist.json", 12),
    ("number-generated.json", 193),
    ("number.json", 37),
    ("param-dict.json", 14),
    ("param-list.json", 20),
    ("param-listlist.json", 3),
    ("string-generated.json", 256),
    ("string.json", 14),
    ("token-generated.json", 256),
    ("token.json", 6),
];
const CORPUS_TOTAL: usize = 1593;

/// Every case fiki answers differently from the corpus for a reason other than the two rules
/// applied to every case (RFC 9651's types and the bounds): the case, whether fiki refuses it, and
/// the decision behind it. A `can_fail` case is always here, because fiki's decisions dictate one
/// outcome for each of them.
const FIKI_WAY: [(&str, bool, &str); 6] = [
    (
        "binary.json/unpadded",
        true,
        "@2g4xxev9: missing padding is refused",
    ),
    (
        "binary.json/partially padded",
        true,
        "@2g4xxev9: partial padding is refused",
    ),
    (
        "binary.json/extra padding",
        true,
        "@2g4xxev9: padding beyond the final quantum is refused",
    ),
    (
        "binary.json/non-zero pad bits",
        false,
        "@2g4xxev9: non-zero pad bits are accepted",
    ),
    // can_fail in the corpus because two field lines are joined inside a string; fiki-py's
    // http_sfv reads the joined value as the string "foo, bar", and so does this port.
    (
        "string.json/two lines string",
        false,
        "fiki-py's outcome for a can_fail case: accepted",
    ),
    // Not can_fail: the corpus parses an empty dictionary, and fiki's entry point refuses a
    // signature header that is present but empty after OWS (@2nyel5g0, pinned by
    // vectors/refusals.json signature-header-of-spaces), as fiki-py's does through http_sfv.
    (
        "dictionary.json/empty dictionary",
        true,
        "@2nyel5g0, refusals.json signature-header-of-spaces",
    ),
];

#[derive(Deserialize)]
struct Case {
    name: String,
    // The serialisation tests carry no raw input, only a value to serialize.
    #[serde(default)]
    raw: Vec<String>,
    header_type: String,
    #[serde(default)]
    expected: Json,
    #[serde(default)]
    must_fail: bool,
    #[serde(default)]
    can_fail: bool,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/third_party/structured-field-tests")
}

fn load(name: &str) -> Vec<Case> {
    let path = corpus_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the httpwg corpus is not at {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"))
}

// The corpus's expected values and this parser's results are both rendered into one notation, so
// a comparison covers the type of every value, the order of members and parameters, and nothing
// else. An integer is i:, a decimal d: at three fractional digits, a string q:, a token t:, a byte
// sequence b: in hex, a boolean ?0 or ?1.

fn decimal(value: f64) -> String {
    format!("d:{value:.3}")
}

fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

fn got_bare(value: &Value) -> String {
    match value {
        Value::Integer(n) => format!("i:{n}"),
        Value::Decimal(text) => decimal(text.parse().expect("a decimal the parser accepted")),
        Value::Text(text) => format!("q:{text:?}"),
        Value::Token(text) => format!("t:{text}"),
        Value::Bytes(raw) => format!("b:{}", hex(raw)),
        Value::Boolean(flag) => format!("?{}", u8::from(*flag)),
    }
}

fn got_params(params: &Params) -> String {
    params
        .iter()
        .map(|(key, value)| format!(";{key}={}", got_bare(value)))
        .collect()
}

fn got_item(item: &Item) -> String {
    got_bare(&item.value) + &got_params(&item.params)
}

fn got_member(member: &Member) -> String {
    match member {
        Member::Item(item) => got_item(item),
        Member::List(list) => {
            let items: Vec<String> = list.items.iter().map(got_item).collect();
            format!("({}){}", items.join(" "), got_params(&list.params))
        }
    }
}

/// RFC 4648 base32, which the corpus uses for a byte sequence's expected value.
fn base32(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for ch in text.bytes().filter(|&c| c != b'=') {
        let at = ALPHABET.iter().position(|&a| a == ch).expect("base32") as u32;
        buffer = (buffer << 5) | at;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

/// Renders an expected value, noting whether it uses a type RFC 9651 added (@7vdhfv3q) and the
/// largest inner list and parameter count it holds, so a case can be refused for exceeding a bound
/// without trusting the parser under test to say so.
#[derive(Default)]
struct Expect {
    rfc9651: bool,
    inner_items: usize,
    params: usize,
}

impl Expect {
    fn bare(&mut self, value: &Json) -> String {
        match value {
            // serde_json reads a literal with "." or an exponent as a float and any other as an
            // integer, so 1.0 stays a decimal and 1 an integer.
            Json::Number(n) if n.is_f64() => decimal(n.as_f64().unwrap()),
            Json::Number(n) => format!("i:{}", n.as_i64().expect("an integer within i64")),
            Json::String(text) => format!("q:{text:?}"),
            Json::Bool(flag) => format!("?{}", u8::from(*flag)),
            Json::Object(typed) => {
                let text = typed["value"].as_str().unwrap_or_default();
                match typed["__type"].as_str() {
                    Some("token") => format!("t:{text}"),
                    Some("binary") => format!("b:{}", hex(&base32(text))),
                    Some("date" | "displaystring") => {
                        self.rfc9651 = true;
                        "rfc9651".into()
                    }
                    other => panic!("an expected type fiki cannot read: {other:?}"),
                }
            }
            other => panic!("an expected bare item fiki cannot read: {other}"),
        }
    }

    fn params(&mut self, value: &Json) -> String {
        let list = value.as_array().expect("parameters");
        self.params = self.params.max(list.len());
        list.iter()
            .map(|pair| {
                let key = pair[0].as_str().expect("a parameter key");
                format!(";{key}={}", self.bare(&pair[1]))
            })
            .collect()
    }

    /// An `[item-or-inner-list, params]` pair; an inner list's value is a JSON array.
    fn member(&mut self, value: &Json) -> String {
        let params = self.params(&value[1]);
        match value[0].as_array() {
            None => self.bare(&value[0]) + &params,
            Some(inner) => {
                self.inner_items = self.inner_items.max(inner.len());
                let items: Vec<String> = inner
                    .iter()
                    .map(|item| self.bare(&item[0]) + &self.params(&item[1]))
                    .collect();
                format!("({}){params}", items.join(" "))
            }
        }
    }
}

/// What the corpus says a successful parse renders as, whether it uses an RFC 9651 type, and
/// whether it exceeds one of fiki's bounds.
fn expect(case: &Case, joined: &str) -> (String, bool, bool) {
    let mut e = Expect::default();
    let (rendered, members) = match case.header_type.as_str() {
        "item" => (e.member(&case.expected), 0),
        "list" => {
            let parts: Vec<String> = case
                .expected
                .as_array()
                .expect("a list")
                .iter()
                .map(|m| e.member(m))
                .collect();
            (format!("[{}]", parts.join(", ")), parts.len())
        }
        "dictionary" => {
            let parts: Vec<String> = case
                .expected
                .as_array()
                .expect("a dictionary")
                .iter()
                .map(|kv| format!("{}={}", kv[0].as_str().expect("a key"), e.member(&kv[1])))
                .collect();
            (format!("{{{}}}", parts.join(", ")), parts.len())
        }
        other => panic!("a header_type fiki does not know: {other}"),
    };
    let over = joined.len() > MAX_FIELD_BYTES
        || members > MAX_DICTIONARY_MEMBERS
        || e.inner_items > MAX_INNER_LIST_ITEMS
        || e.params > MAX_PARAMETERS;
    (rendered, e.rfc9651, over)
}

fn malformed() -> Error {
    Error::new(KIND, "I could not parse the field.")
}

/// The list entry point: the size bound on the combined value, the parser, then the count bounds.
fn bounded_list(raw: &str) -> crate::Result<Vec<Member>> {
    check_size(raw, NAME, KIND)?;
    let parsed = parse_list(raw).map_err(|_| malformed())?;
    check_counts(parsed.iter(), NAME, KIND)?;
    Ok(parsed)
}

/// The item entry point, bounded as a list is.
fn bounded_item(raw: &str) -> crate::Result<Item> {
    check_size(raw, NAME, KIND)?;
    let parsed = Member::Item(parse_item(raw).map_err(|_| malformed())?);
    check_counts(std::iter::once(&parsed), NAME, KIND)?;
    match parsed {
        Member::Item(item) => Ok(item),
        Member::List(_) => unreachable!(),
    }
}

/// One case through its entry point, rendered, or `None` for a refusal. A refusal must be the entry
/// point's own malformed kind; anything else fails the test.
fn parse_case(header_type: &str, raw: &str) -> Result<Option<String>, String> {
    let parsed = match header_type {
        "dictionary" => parse_bounded(raw, NAME, KIND).map(|members| {
            let parts: Vec<String> = members
                .iter()
                .map(|(key, member)| format!("{key}={}", got_member(member)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }),
        "list" => bounded_list(raw).map(|members| {
            let parts: Vec<String> = members.iter().map(got_member).collect();
            format!("[{}]", parts.join(", "))
        }),
        "item" => bounded_item(raw).map(|item| got_item(&item)),
        other => return Err(format!("a header_type fiki does not know: {other}")),
    };
    match parsed {
        Ok(rendered) => Ok(Some(rendered)),
        Err(e) if e.kind == KIND => Ok(None),
        Err(e) => Err(format!("a refusal that is not {KIND}: {e:?}")),
    }
}

fn clip(text: &str) -> String {
    text.chars().take(300).collect()
}

#[test]
fn the_httpwg_corpus() {
    let mut files: Vec<String> = std::fs::read_dir(corpus_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".json"))
        .collect();
    files.sort();
    let pinned: Vec<&str> = CORPUS_COUNTS.iter().map(|(name, _)| *name).collect();
    assert_eq!(files, pinned, "the corpus's files and the pinned ones");

    let fiki_way: BTreeMap<&str, bool> = FIKI_WAY.iter().map(|(id, r, _)| (*id, *r)).collect();
    let mut used = Vec::new();
    let mut failures = Vec::new();
    let mut total = 0;
    for (file, count) in CORPUS_COUNTS {
        let cases = load(file);
        let mut ran = 0;
        for case in &cases {
            ran += 1;
            let id = format!("{file}/{}", case.name);
            let joined = case.raw.join(", ");
            let got = match parse_case(&case.header_type, &joined) {
                Ok(got) => got,
                Err(why) => {
                    failures.push(format!("{id}: {why}"));
                    continue;
                }
            };
            let (want, rfc9651, over) = if case.must_fail {
                (String::new(), false, false)
            } else {
                expect(case, &joined)
            };
            let excepted = fiki_way.get(id.as_str()).copied();
            // RFC 9651's types decide a can_fail Date or Display String: refused.
            if case.can_fail && excepted.is_none() && !rfc9651 {
                failures.push(format!(
                    "{id}: a can_fail case with no outcome decided for fiki"
                ));
                continue;
            }
            let mut refuse = case.must_fail || rfc9651 || over;
            if (file == "date.json" || file == "display-string.json") && !refuse {
                failures.push(format!("{id}: an RFC 9651 case fiki would not refuse"));
                continue;
            }
            if let Some(refused) = excepted {
                used.push(id.clone());
                refuse = refused;
            }
            match (refuse, got) {
                (true, Some(got)) => failures.push(format!(
                    "{id}: fiki refuses {:?}, and this port parsed it as {}",
                    clip(&joined),
                    clip(&got)
                )),
                (false, None) => failures.push(format!(
                    "{id}: the corpus parses {:?} as {}, and this port refused it",
                    clip(&joined),
                    clip(&want)
                )),
                (false, Some(got)) if got != want => failures.push(format!(
                    "{id}: {:?} parsed as {}, and the corpus says {}",
                    clip(&joined),
                    clip(&got),
                    clip(&want)
                )),
                _ => {}
            }
        }
        assert_eq!(
            (cases.len(), ran),
            (count, count),
            "{file}: cases held and run, against {count} pinned, 0 skipped"
        );
        total += ran;
    }
    assert_eq!(total, CORPUS_TOTAL, "corpus parse cases run");
    for (id, _, _) in FIKI_WAY {
        assert!(
            used.iter().any(|u| u == id),
            "an exception for {id}, which the corpus no longer holds"
        );
    }
    assert!(
        failures.is_empty(),
        "{} corpus cases disagree:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The corpus has no item whose parameters fail to parse, so these are named.
#[test]
fn an_item_whose_parameters_are_malformed_is_refused() {
    for raw in ["1;", "1;A=2", r#""a";b="\x""#] {
        assert!(bounded_item(raw).is_err(), "{raw:?}");
    }
}

fn first<'a>(case: &'a Case, file: &str) -> &'a Json {
    assert!(
        case.must_fail,
        "{file}/{}: a value the corpus serializes",
        case.name
    );
    &case.expected[0]
}

/// The serialisation subset, through the public signing API. Every case it runs is one the corpus
/// says must not serialize, so each must be refused before anything is signed.
#[test]
fn the_httpwg_serialisation_cases() {
    let key = Key::from_seed(&[7u8; 32]).unwrap();
    let sign = |opts: SignOptions| {
        let opts = SignOptions {
            created: opts.created.or(Some(1_700_000_000)),
            ..opts
        };
        sign_request(
            &key,
            "GET",
            "https://api.example.com/x",
            &BTreeMap::new(),
            &opts,
        )
    };
    let dir = "serialisation-tests";

    // A key is refused as a label, the caller's mistake; and as a covered component's parameter
    // key, where every port reports UnsupportedComponent: the spec string is read as an RFC 8941
    // serialization, and one that does not read as one is a component fiki cannot name.
    let mut keys = 0;
    for case in load(&format!("{dir}/key-generated.json")) {
        let value = first(&case, "key-generated.json");
        let k = match case.header_type.as_str() {
            "list" => value[1][0][0].as_str(),
            _ => value[0].as_str(),
        }
        .expect("a key")
        .to_string();
        let err = sign(SignOptions {
            label: Some(k.clone()),
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            err.kind == Kind::InvalidArgument && err.message.contains("is not an RFC 8941 key"),
            "{}: label {k:?} gave {err:?}",
            case.name
        );
        let err = sign(SignOptions {
            covered: Some(vec!["@method".into(), format!("\"@path\";{k}")]),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(
            err.kind,
            Kind::UnsupportedComponent,
            "{}: parameter key {k:?} gave {err:?}",
            case.name
        );
        keys += 1;
    }

    let mut strings = 0;
    for case in load(&format!("{dir}/string-generated.json")) {
        let s = first(&case, "string-generated.json")
            .as_str()
            .expect("a string")
            .to_string();
        for opts in [
            SignOptions {
                keyid: Some(s.clone()),
                ..Default::default()
            },
            SignOptions {
                nonce: Some(s.clone()),
                ..Default::default()
            },
            SignOptions {
                tag: Some(s.clone()),
                ..Default::default()
            },
        ] {
            let err = sign(opts).unwrap_err();
            assert!(
                err.kind == Kind::InvalidArgument
                    && err.message.contains("outside printable ASCII"),
                "{}: {s:?} gave {err:?}",
                case.name
            );
        }
        strings += 1;
    }

    // created is an i64, so the two too-big decimals have no Rust spelling and are skipped: the
    // type system refuses them before fiki is called.
    let (mut numbers, mut skipped) = (0, 0);
    for case in load(&format!("{dir}/number.json")) {
        if !case.name.starts_with("too big") {
            continue;
        }
        let Some(created) = first(&case, "number.json").as_i64() else {
            skipped += 1;
            continue;
        };
        let err = sign(SignOptions {
            created: Some(created),
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            err.kind == Kind::InvalidArgument
                && err
                    .message
                    .contains("fiki signs one from 0 to 999999999999999"),
            "{}: created {created} gave {err:?}",
            case.name
        );
        numbers += 1;
    }

    assert_eq!(
        (keys, strings, numbers, skipped),
        (378, 33, 2, 2),
        "key, string and number cases run, and number cases skipped"
    );
}

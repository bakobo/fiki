//! The RFC 8941 subset RFC 9421 actually uses (`this.i` @2q9gv70t, @2tt6fmc0, @5e2phpjy).
//!
//! Hand-rolled rather than depended upon, for the reason every port hand-rolls it: fiki's slice of
//! structured fields is small and CLOSED — dictionaries whose members are inner lists of strings
//! with parameters, plus byte sequences — and the shared vectors pin its entire output surface byte
//! for byte. The usual argument against writing your own parser holds where the grammar is
//! open-ended; this one's every output is checked against committed bytes shared with four other
//! implementations.
//!
//! It reads the whole of RFC 8941's bare-item grammar, tokens and decimals included, even though
//! fiki accepts neither anywhere. A header fiki-py's parser reads must be classified the same way
//! here: `alg=ed25519` is a signature parameter of the wrong type, not an unparsable header, and
//! the two are different refusals.

use std::collections::HashMap;

use crate::keys::{b64std, b64std_decode};

/// A bare item. The variants are RFC 8941's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Text(String),
    Token(String),
    Integer(i64),
    /// Kept as written: fiki refuses every decimal it meets, so it never does arithmetic on one.
    Decimal(String),
    Boolean(bool),
    Bytes(Vec<u8>),
}

pub(crate) type Params = Vec<(String, Value)>;

/// A bare item with its parameters — a covered component such as `"@path";req`, or a dictionary
/// member's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Item {
    pub value: Value,
    pub params: Params,
}

impl Item {
    pub fn text(&self) -> Option<&str> {
        match &self.value {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }
}

/// A covered-component list with its signature parameters, in the order they arrived.
///
/// Order is load-bearing on the verify side: a verifier that reorders what it received computes a
/// different base and rejects a good signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InnerList {
    pub items: Vec<Item>,
    pub params: Params,
}

impl InnerList {
    pub fn param(&self, key: &str) -> Option<&Value> {
        self.params.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Member {
    Item(Item),
    List(InnerList),
}

/// This module's own failure. It never escapes: the parser cannot know WHICH header it is reading,
/// and the taxonomy distinguishes an unparsable Signature from an unparsable Signature-Input, so
/// callers translate it into the kind that names the header.
#[derive(Debug)]
pub(crate) struct SyntaxError;

type Parsed<T> = std::result::Result<T, SyntaxError>;

/// RFC 8941's map semantics, which both dictionaries and parameters have: a repeated key keeps its
/// first position and takes its last value. Indexed, because the input is untrusted and a linear
/// search per key would make a long parameter list quadratic (bakobo/fiki#8).
struct Ordered<T> {
    entries: Vec<(String, T)>,
    index: HashMap<String, usize>,
}

impl<T> Ordered<T> {
    fn new() -> Self {
        Ordered {
            entries: Vec::new(),
            index: HashMap::new(),
        }
    }

    fn put(&mut self, key: String, value: T) {
        match self.index.get(&key) {
            Some(&at) => self.entries[at].1 = value,
            None => {
                self.index.insert(key.clone(), self.entries.len());
                self.entries.push((key, value));
            }
        }
    }
}

struct Cursor<'a> {
    text: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn done(&self) -> bool {
        self.at >= self.text.len()
    }

    fn peek(&self) -> u8 {
        if self.done() {
            0
        } else {
            self.text[self.at]
        }
    }

    fn take(&mut self) -> Parsed<u8> {
        if self.done() {
            return Err(SyntaxError);
        }
        self.at += 1;
        Ok(self.text[self.at - 1])
    }

    fn skip(&mut self, chars: &[u8]) {
        while !self.done() && chars.contains(&self.peek()) {
            self.at += 1;
        }
    }

    fn expect(&mut self, ch: u8) -> Parsed<()> {
        if self.take()? != ch {
            return Err(SyntaxError);
        }
        Ok(())
    }

    fn slice(&self, start: usize) -> String {
        // Every byte a caller slices over has been checked to be ASCII.
        String::from_utf8_lossy(&self.text[start..self.at]).into_owned()
    }

    fn parse_key(&mut self) -> Parsed<String> {
        let start = self.at;
        if !(self.peek().is_ascii_lowercase() || self.peek() == b'*') {
            return Err(SyntaxError);
        }
        while self.peek().is_ascii_lowercase()
            || self.peek().is_ascii_digit()
            || matches!(self.peek(), b'_' | b'-' | b'.' | b'*')
        {
            self.at += 1;
        }
        Ok(self.slice(start))
    }

    fn parse_string(&mut self) -> Parsed<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.take()? {
                b'\\' => match self.take()? {
                    esc @ (b'"' | b'\\') => out.push(esc as char),
                    _ => return Err(SyntaxError),
                },
                b'"' => return Ok(out),
                // Visible ASCII and space only (RFC 8941 section 3.3.3).
                ch @ 0x20..=0x7e => out.push(ch as char),
                _ => return Err(SyntaxError),
            }
        }
    }

    fn parse_token(&mut self) -> Parsed<String> {
        let start = self.at;
        self.at += 1; // the first character, which the caller checked is ALPHA or "*"
        while !self.done()
            && (self.peek().is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&self.peek()))
        {
            self.at += 1;
        }
        Ok(self.slice(start))
    }

    fn parse_byte_sequence(&mut self) -> Parsed<Vec<u8>> {
        self.expect(b':')?;
        let start = self.at;
        while self.peek().is_ascii_alphanumeric() || matches!(self.peek(), b'+' | b'/' | b'=') {
            self.at += 1;
        }
        let encoded = self.slice(start);
        self.expect(b':')?;
        b64std_decode(&encoded).ok_or(SyntaxError)
    }

    fn parse_number(&mut self) -> Parsed<Value> {
        let start = self.at;
        if self.peek() == b'-' {
            self.at += 1;
        }
        let digits = self.at;
        self.skip(b"0123456789");
        let whole = self.at - digits;
        if whole == 0 {
            return Err(SyntaxError);
        }
        if self.peek() != b'.' {
            if whole > 15 {
                return Err(SyntaxError);
            }
            return self
                .slice(start)
                .parse()
                .map(Value::Integer)
                .map_err(|_| SyntaxError);
        }
        self.at += 1;
        let fraction = self.at;
        self.skip(b"0123456789");
        if whole > 12 || !(1..=3).contains(&(self.at - fraction)) {
            return Err(SyntaxError);
        }
        Ok(Value::Decimal(self.slice(start)))
    }

    fn parse_bare_item(&mut self) -> Parsed<Value> {
        match self.peek() {
            b'"' => Ok(Value::Text(self.parse_string()?)),
            b':' => Ok(Value::Bytes(self.parse_byte_sequence()?)),
            b'?' => {
                self.at += 1;
                match self.take()? {
                    b'0' => Ok(Value::Boolean(false)),
                    b'1' => Ok(Value::Boolean(true)),
                    _ => Err(SyntaxError),
                }
            }
            ch if ch == b'-' || ch.is_ascii_digit() => self.parse_number(),
            ch if ch.is_ascii_alphabetic() || ch == b'*' => Ok(Value::Token(self.parse_token()?)),
            _ => Err(SyntaxError),
        }
    }

    fn parse_parameters(&mut self) -> Parsed<Params> {
        let mut params = Ordered::new();
        while self.peek() == b';' {
            self.at += 1;
            self.skip(b" ");
            let key = self.parse_key()?;
            let value = if self.peek() == b'=' {
                self.at += 1;
                self.parse_bare_item()?
            } else {
                Value::Boolean(true)
            };
            params.put(key, value);
        }
        Ok(params.entries)
    }

    fn parse_item(&mut self) -> Parsed<Item> {
        Ok(Item {
            value: self.parse_bare_item()?,
            params: self.parse_parameters()?,
        })
    }

    fn parse_inner_list(&mut self) -> Parsed<InnerList> {
        self.expect(b'(')?;
        let mut items = Vec::new();
        loop {
            self.skip(b" ");
            if self.peek() == b')' {
                self.at += 1;
                break;
            }
            items.push(self.parse_item()?);
            if !matches!(self.peek(), b' ' | b')') {
                return Err(SyntaxError);
            }
        }
        Ok(InnerList {
            items,
            params: self.parse_parameters()?,
        })
    }
}

fn whole<T>(text: &str, parse: impl FnOnce(&mut Cursor) -> Parsed<T>) -> Parsed<T> {
    // RFC 8941 section 4.2: leading and trailing spaces are discarded, and nothing else may remain.
    let mut cursor = Cursor {
        text: text.trim_matches(' ').as_bytes(),
        at: 0,
    };
    let out = parse(&mut cursor)?;
    if !cursor.done() {
        return Err(SyntaxError);
    }
    Ok(out)
}

/// Parse an RFC 8941 dictionary, preserving member order because the verify side depends on it.
pub(crate) fn parse_dictionary(text: &str) -> Parsed<Vec<(String, Member)>> {
    whole(text, |cursor| {
        let mut out = Ordered::new();
        while !cursor.done() {
            let key = cursor.parse_key()?;
            let member = if cursor.peek() == b'=' {
                cursor.at += 1;
                if cursor.peek() == b'(' {
                    Member::List(cursor.parse_inner_list()?)
                } else {
                    Member::Item(cursor.parse_item()?)
                }
            } else {
                Member::Item(Item {
                    value: Value::Boolean(true),
                    params: cursor.parse_parameters()?,
                })
            };
            out.put(key, member);
            cursor.skip(b" \t");
            if cursor.done() {
                break;
            }
            cursor.expect(b',')?;
            cursor.skip(b" \t");
            if cursor.done() {
                return Err(SyntaxError);
            }
        }
        Ok(out.entries)
    })
}

/// Parse one RFC 8941 item with its parameters, such as `"@path";req`.
pub(crate) fn parse_item(text: &str) -> Parsed<Item> {
    whole(text, |cursor| cursor.parse_item())
}

fn serialize_bare_item(value: &Value) -> String {
    match value {
        Value::Text(text) => format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\"")),
        Value::Token(text) | Value::Decimal(text) => text.clone(),
        Value::Integer(n) => n.to_string(),
        Value::Bytes(raw) => format!(":{}:", b64std(raw)),
        Value::Boolean(flag) => format!("?{}", u8::from(*flag)),
    }
}

pub(crate) fn serialize_parameters(params: &[(String, Value)]) -> String {
    params
        .iter()
        .map(|(key, value)| match value {
            // RFC 8941 renders a true-valued parameter as a bare key.
            Value::Boolean(true) => format!(";{key}"),
            _ => format!(";{key}={}", serialize_bare_item(value)),
        })
        .collect()
}

/// Render an item with its parameters: `"@path";req`.
pub(crate) fn serialize_item(item: &Item) -> String {
    format!(
        "{}{}",
        serialize_bare_item(&item.value),
        serialize_parameters(&item.params)
    )
}

/// Render a covered-component list with its signature parameters.
pub(crate) fn serialize_inner_list(list: &InnerList) -> String {
    let items: Vec<String> = list.items.iter().map(serialize_item).collect();
    format!(
        "({}){}",
        items.join(" "),
        serialize_parameters(&list.params)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(text: &str) -> Item {
        parse_item(text).unwrap()
    }

    #[test]
    fn every_bare_item_type_parses_and_serializes_back() {
        for text in [
            r#""a \"quoted\" \\ string""#,
            "token/with:colon*",
            "*star",
            "-42",
            "1.5",
            "-0.125",
            "?0",
            "?1",
            ":AQID:",
            r#""@path";req;x=?0;y=tok;z=1.25"#,
        ] {
            assert_eq!(serialize_item(&item(text)), text, "{text}");
        }
    }

    #[test]
    fn malformed_items_are_refused() {
        for text in [
            "",
            "\"unterminated",
            "\"bad \\escape\"",
            "\"caf\u{e9}\"",
            "\"tab\there\"",
            ":AQI!:",
            ":AQID",
            "?2",
            "?",
            "-",
            "1234567890123456",
            "1234567890123.5",
            "1.",
            "1.2345",
            "a;",
            "a;B",
            "a b",
            "@x",
        ] {
            assert!(parse_item(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn a_repeated_parameter_keeps_its_place_and_takes_its_last_value() {
        assert_eq!(serialize_item(&item("a;x=1;y;x=2")), "a;x=2;y");
    }

    #[test]
    fn dictionaries() {
        let parsed = parse_dictionary(r#" a=("x" "y";req);k=1, b=:AQID:;p, c, a=?0 "#).unwrap();
        let keys: Vec<&str> = parsed.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["a", "b", "c"]);
        assert_eq!(parsed[0].1, Member::Item(item("?0")));
        assert_eq!(parsed[2].1, Member::Item(item("?1")));
        match &parsed[1].1 {
            Member::Item(found) => assert_eq!(serialize_item(found), ":AQID:;p"),
            other => panic!("{other:?}"),
        }
        let list = match &parse_dictionary(r#"a=( "x"  "y";req );k=1"#).unwrap()[0].1 {
            Member::List(list) => list.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(serialize_inner_list(&list), r#"("x" "y";req);k=1"#);
        assert_eq!(list.param("k"), Some(&Value::Integer(1)));
        assert_eq!(list.param("absent"), None);
        assert_eq!(item("\"s\"").text(), Some("s"));
        assert_eq!(item("tok").text(), None);
        for text in [
            "a=1,",
            "a=1 b=2",
            "A=1",
            "a=(\"x\"\"y\")",
            "a=(\"x\"",
            "a=1;",
        ] {
            assert!(parse_dictionary(text).is_err(), "{text:?}");
        }
        assert!(parse_dictionary("").unwrap().is_empty());
    }
}

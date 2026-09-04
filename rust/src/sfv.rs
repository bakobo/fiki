//! The RFC 8941 subset RFC 9421 actually uses (`this.i` @2q9gv70t, @2tt6fmc0).
//!
//! Hand-rolled rather than depended upon, for the reason every port hand-rolls it: fiki's slice of
//! structured fields is small and CLOSED — a dictionary whose members are inner lists of strings
//! with parameters, plus byte sequences — and the shared vectors pin its entire output surface byte
//! for byte. The usual argument against writing your own parser holds where the grammar is
//! open-ended; this one's every output is checked against committed bytes shared with four other
//! implementations.

use crate::keys::{b64std, b64std_decode};

/// A parameter value. The variants are exactly what RFC 9421 puts in these two headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Text(String),
    Integer(i64),
    Boolean(bool),
    Bytes(Vec<u8>),
}

/// A covered-component list with its signature parameters, in the order they arrived.
///
/// Order is load-bearing on the verify side: a verifier that reorders what it received computes a
/// different base and rejects a good signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InnerList {
    pub items: Vec<String>,
    pub params: Vec<(String, Value)>,
}

impl InnerList {
    pub fn param(&self, key: &str) -> Option<&Value> {
        self.params.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Member {
    pub list: InnerList,
    pub value: Option<Value>,
}

/// This module's own failure. It never escapes: the parser cannot know WHICH header it is reading,
/// and the taxonomy distinguishes an unparsable Signature from an unparsable Signature-Input, so
/// callers translate it into the kind that names the header.
#[derive(Debug)]
pub(crate) struct SyntaxError;

type Parsed<T> = std::result::Result<T, SyntaxError>;

struct Cursor<'a> {
    text: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
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

    fn skip_space(&mut self) {
        while !self.done() && (self.peek() == b' ' || self.peek() == b'\t') {
            self.at += 1;
        }
    }

    fn expect(&mut self, ch: u8) -> Parsed<()> {
        if self.done() || self.peek() != ch {
            return Err(SyntaxError);
        }
        self.at += 1;
        Ok(())
    }

    fn parse_key(&mut self) -> Parsed<String> {
        let start = self.at;
        if self.done() || !(self.peek().is_ascii_lowercase() || self.peek() == b'*') {
            return Err(SyntaxError);
        }
        while !self.done()
            && (self.peek().is_ascii_lowercase()
                || self.peek().is_ascii_digit()
                || matches!(self.peek(), b'_' | b'-' | b'.' | b'*'))
        {
            self.at += 1;
        }
        String::from_utf8(self.text[start..self.at].to_vec()).map_err(|_| SyntaxError)
    }

    fn parse_string(&mut self) -> Parsed<String> {
        self.at += 1; // the opening quote, which the caller already peeked
        let mut out = String::new();
        while !self.done() {
            let ch = self.text[self.at];
            self.at += 1;
            match ch {
                b'\\' => {
                    if self.done() {
                        return Err(SyntaxError);
                    }
                    let esc = self.text[self.at];
                    self.at += 1;
                    if esc != b'"' && esc != b'\\' {
                        return Err(SyntaxError);
                    }
                    out.push(esc as char);
                }
                b'"' => return Ok(out),
                _ => out.push(ch as char),
            }
        }
        Err(SyntaxError)
    }

    fn parse_byte_sequence(&mut self) -> Parsed<Vec<u8>> {
        self.at += 1; // the opening colon
        let start = self.at;
        while !self.done() && self.peek() != b':' {
            self.at += 1;
        }
        let encoded = std::str::from_utf8(&self.text[start..self.at]).map_err(|_| SyntaxError)?;
        let encoded = encoded.to_owned();
        self.expect(b':')?;
        b64std_decode(&encoded).ok_or(SyntaxError)
    }

    fn parse_integer(&mut self) -> Parsed<i64> {
        let start = self.at;
        if self.peek() == b'-' {
            self.at += 1;
        }
        while !self.done() && self.peek().is_ascii_digit() {
            self.at += 1;
        }
        std::str::from_utf8(&self.text[start..self.at])
            .map_err(|_| SyntaxError)?
            .parse()
            .map_err(|_| SyntaxError)
    }

    fn parse_bare_item(&mut self) -> Parsed<Value> {
        match self.peek() {
            b'"' => Ok(Value::Text(self.parse_string()?)),
            b':' => Ok(Value::Bytes(self.parse_byte_sequence()?)),
            b'?' => {
                self.at += 1;
                if self.done() {
                    return Err(SyntaxError);
                }
                let flag = self.text[self.at];
                self.at += 1;
                match flag {
                    b'0' => Ok(Value::Boolean(false)),
                    b'1' => Ok(Value::Boolean(true)),
                    _ => Err(SyntaxError),
                }
            }
            ch if ch == b'-' || ch.is_ascii_digit() => Ok(Value::Integer(self.parse_integer()?)),
            _ => Err(SyntaxError),
        }
    }

    fn parse_parameters(&mut self) -> Parsed<Vec<(String, Value)>> {
        let mut params = Vec::new();
        while !self.done() && self.peek() == b';' {
            self.at += 1;
            self.skip_space();
            let key = self.parse_key()?;
            if !self.done() && self.peek() == b'=' {
                self.at += 1;
                params.push((key, self.parse_bare_item()?));
            } else {
                params.push((key, Value::Boolean(true)));
            }
        }
        Ok(params)
    }

    fn parse_inner_list(&mut self) -> Parsed<InnerList> {
        self.at += 1; // the opening parenthesis
        let mut items = Vec::new();
        loop {
            self.skip_space();
            if self.done() {
                return Err(SyntaxError);
            }
            if self.peek() == b')' {
                self.at += 1;
                break;
            }
            let item = match self.parse_bare_item()? {
                Value::Text(text) => text,
                // fiki's covered components are strings; anything else is a shape it cannot
                // render back.
                _ => return Err(SyntaxError),
            };
            // RFC 9421 never puts parameters on the members of a covered-component list.
            if !self.done() && self.peek() == b';' {
                return Err(SyntaxError);
            }
            if !self.done() && self.peek() != b' ' && self.peek() != b')' {
                return Err(SyntaxError);
            }
            items.push(item);
        }
        Ok(InnerList {
            items,
            params: self.parse_parameters()?,
        })
    }
}

/// Parse an RFC 8941 dictionary, preserving member order because the verify side depends on it.
pub(crate) fn parse_dictionary(text: &str) -> Parsed<Vec<(String, Member)>> {
    let mut cursor = Cursor {
        text: text.as_bytes(),
        at: 0,
    };
    let mut out: Vec<(String, Member)> = Vec::new();
    cursor.skip_space();
    while !cursor.done() {
        let key = cursor.parse_key()?;
        let member = if !cursor.done() && cursor.peek() == b'=' {
            cursor.at += 1;
            if cursor.peek() == b'(' {
                Member {
                    list: cursor.parse_inner_list()?,
                    value: None,
                }
            } else {
                let value = cursor.parse_bare_item()?;
                let params = cursor.parse_parameters()?;
                Member {
                    list: InnerList {
                        items: Vec::new(),
                        params,
                    },
                    value: Some(value),
                }
            }
        } else {
            let params = cursor.parse_parameters()?;
            Member {
                list: InnerList {
                    items: Vec::new(),
                    params,
                },
                value: Some(Value::Boolean(true)),
            }
        };
        out.retain(|(existing, _)| existing != &key);
        out.push((key, member));
        cursor.skip_space();
        if cursor.done() {
            break;
        }
        cursor.expect(b',')?;
        cursor.skip_space();
        if cursor.done() {
            return Err(SyntaxError);
        }
    }
    Ok(out)
}

fn serialize_bare_item(value: &Value) -> String {
    match value {
        Value::Text(text) => format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\"")),
        Value::Integer(n) => n.to_string(),
        Value::Bytes(raw) => format!(":{}:", b64std(raw)),
        // Only `false` reaches here: RFC 8941 renders a true-valued parameter as a bare key, which
        // serialize_parameters does before calling this, and fiki never puts a boolean in an item
        // position.
        Value::Boolean(_) => "?0".to_string(),
    }
}

fn serialize_parameters(params: &[(String, Value)]) -> String {
    params
        .iter()
        .map(|(key, value)| match value {
            Value::Boolean(true) => format!(";{key}"),
            _ => format!(";{key}={}", serialize_bare_item(value)),
        })
        .collect()
}

/// Render a covered-component list with its signature parameters.
pub(crate) fn serialize_inner_list(list: &InnerList) -> String {
    let items: Vec<String> = list
        .items
        .iter()
        .map(|item| serialize_bare_item(&Value::Text(item.clone())))
        .collect();
    format!(
        "({}){}",
        items.join(" "),
        serialize_parameters(&list.params)
    )
}

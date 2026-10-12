//! Other spellings of an Ed25519 key, read at the edge of the API (`this.i` @0mvgkwnl).
//!
//! [`aid_from`] turns a public key spelled as an AID, as raw base64url (the wire keyid of
//! @7xrx5evg, also a JWK's `x`), as a base58btc did:key, as a did:peer with numalgo 0, or as an
//! OpenSSH public line into the canonical AID. The OpenSSH private-key reader is `openssh.rs`.
//!
//! Nothing here touches a request. A verifier calls [`aid_from`] when it loads its registrations,
//! so a bad one fails at configuration time rather than on a live request, and `expected_aid` stays
//! a single spelling. Every spelling has exactly one accepted form: each decoder below refuses any
//! text that is not the one spelling of what it decoded, so no key has two spellings that both
//! pass. Every decoded key then goes through the same point check as a keyid, so no spelling is a
//! way around the small-order refusal (@37wdchu5).

use ed25519_dalek::VerifyingKey;

use crate::errors::{Error, Kind, Result};
use crate::keys::{aid_of, b64url, decode, public_key, y_below_prime, URL_ALPHABET};
use crate::openssh::{b64std_canonical, ssh_public_blob};

/// The most characters any public spelling may have, checked before anything is decoded, so
/// nothing below ever sees more (input-handling standard: size, then shape, then meaning). An
/// OpenSSH public line's comment is the only part of any spelling that varies much, and 1024
/// characters leaves it ample room.
pub(crate) const MAX_PUBLIC_CHARS: usize = 1024;

const RAW_LEN: usize = 32;
const AID_LEN: usize = 44;
const RAW_B64URL_LEN: usize = 43;
/// multicodec ed25519-pub, 0xed as an unsigned varint. Exactly these two bytes, so a non-minimal
/// varint cannot name the same codec twice.
const ED25519_PUB: [u8; 2] = [0xed, 0x01];
/// A base58btc value over 34 bytes is at most 47 characters after the "z"; anything longer cannot
/// be an Ed25519 did:key, and refusing it first keeps base58's arithmetic to a fixed size.
const MAX_MULTIBASE: usize = 48;

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Unpadded base64url, or `None` unless `text` is the one canonical spelling of its bytes.
fn b64url_canonical(text: &str) -> Option<Vec<u8>> {
    if !text.bytes().all(|b| URL_ALPHABET.contains(&b)) {
        return None;
    }
    let data = decode(text, URL_ALPHABET)?;
    (b64url(&data) == text).then_some(data)
}

/// base58btc, or `None`. Each leading "1" is one zero byte and the rest is a big-endian number
/// written without leading zeros, so every string has exactly one meaning and re-encodes to itself:
/// a leading "1" cannot add a zero byte that another spelling of the same bytes lacks.
pub(crate) fn b58_decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() {
        return None;
    }
    let zeros = text.bytes().take_while(|b| *b == b'1').count();
    // Big-endian, and never with a leading zero byte: the first digit after the "1"s is non-zero.
    let mut number: Vec<u8> = Vec::new();
    for ch in text.bytes() {
        let mut carry = B58.iter().position(|c| *c == ch)? as u32;
        for byte in number.iter_mut().rev() {
            carry += *byte as u32 * 58;
            *byte = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            number.insert(0, carry as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(number);
    Some(out)
}

/// The raw key under a did:key multibase value, which is base58btc ("z") only.
///
/// The did:key ABNF also admits base64url ("u"), but the spec's resolution algorithm requires the
/// value to "begin with the letter `z`" or raise invalidDid, and the peer DID ABNF has
/// transform = "z". Reading "u" too would give every key two DIDs.
fn multibase_ed25519(value: &str) -> Option<[u8; RAW_LEN]> {
    if value.len() > MAX_MULTIBASE {
        return None;
    }
    let decoded = b58_decode(value.strip_prefix('z')?)?;
    if decoded.len() != ED25519_PUB.len() + RAW_LEN || decoded[..2] != ED25519_PUB {
        return None;
    }
    decoded[2..].try_into().ok()
}

/// The 32 bytes under a 44-character B, D or E AID, or `None` unless it is spelled canonically.
///
/// An AID is base64url over a zero pad byte and the bytes, with the pad's character replaced by the
/// code; only the spelling `to_aid` produces, code aside, is an AID (bakobo/fiki#4).
fn aid_body(text: &str) -> Option<[u8; RAW_LEN]> {
    if text.len() != AID_LEN || !b"BDE".contains(&text.as_bytes()[0]) {
        return None;
    }
    let decoded = b64url_canonical(&format!("A{}", &text[1..]))?;
    let raw: [u8; RAW_LEN] = decoded[1..].try_into().ok()?;
    (aid_of(&raw)[1..] == text[1..]).then_some(raw)
}

/// "ssh-ed25519", one space, the blob, and optionally one space and a printable-ASCII comment that
/// neither begins nor ends with a space, so that no whitespace around any field is ever ignored.
fn ssh_line(text: &str) -> Option<[u8; RAW_LEN]> {
    let rest = text.strip_prefix("ssh-ed25519 ")?;
    let (blob, comment) = match rest.split_once(' ') {
        Some((blob, comment)) => (blob, Some(comment)),
        None => (rest, None),
    };
    let blob_ok = !blob.is_empty()
        && blob
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b));
    let comment_ok = comment.map_or(true, |c| {
        let bytes = c.as_bytes();
        !bytes.is_empty()
            && bytes.iter().all(|b| (0x20..=0x7e).contains(b))
            && bytes[0] != b' '
            && bytes[bytes.len() - 1] != b' '
    });
    if !blob_ok || !comment_ok {
        return None;
    }
    ssh_public_blob(&b64std_canonical(blob)?)
}

/// The raw key `text` spells, by its shape, or `None` for a shape fiki does not read.
fn raw_of(text: &str) -> Option<[u8; RAW_LEN]> {
    if text.len() == AID_LEN && text.starts_with('B') {
        return aid_body(text);
    }
    if text.len() == RAW_B64URL_LEN {
        return b64url_canonical(text)?.try_into().ok();
    }
    if let Some(value) = text.strip_prefix("did:key:") {
        return multibase_ed25519(value);
    }
    if let Some(value) = text.strip_prefix("did:peer:0") {
        return multibase_ed25519(value);
    }
    ssh_line(text)
}

fn refuse(message: String) -> Error {
    // Error::new leaves the detail empty: what reaches here can be a private key, so it must not be
    // carried anywhere a consumer might log it (@0mvgkwnl).
    Error::new(Kind::MalformedKey, message)
}

/// The canonical AID of the Ed25519 public key `text` spells (`this.i` @0mvgkwnl).
///
/// `text` is an AID, the raw key as 43 characters of unpadded base64url (a JWK's `x`), a base58btc
/// did:key, a did:peer with numalgo 0, or an OpenSSH public line — `ssh-ed25519`, one space, the
/// blob, and optionally one space and a printable-ASCII comment that neither begins nor ends with a
/// space. Length, not the first character, tells raw from AID: 43 against 44. Nothing around
/// `text` is stripped; that is the caller's, so that one input never has two readings. Call it when
/// you load registrations rather than per request.
///
/// Anything else is `Kind::MalformedKey`, including a transferable or digest AID, whose key is not
/// the identifier's to give. The error never quotes `text` and its `detail` is `None`, because what
/// is handed here by mistake can be a private key: the `.key` file instead of the `.pub`, or a
/// seed, which in base64url is 43 characters like a raw key.
pub fn aid_from(text: &str) -> Result<String> {
    // Bounded first, and the count itself stops one past the bound however long `text` is.
    if text.chars().nth(MAX_PUBLIC_CHARS).is_some() {
        return Err(refuse(format!(
            "A public key is at most {MAX_PUBLIC_CHARS} characters in any spelling fiki reads; \
             this one is longer."
        )));
    }
    // Shape before meaning: only a canonically spelled D or E AID is told what it is.
    if (text.starts_with('D') || text.starts_with('E')) && aid_body(text).is_some() {
        return Err(refuse(
            "The text is a transferable or digest AID, whose current key is not recoverable from \
             the identifier; resolve it to a key first."
                .into(),
        ));
    }
    let raw = raw_of(text).ok_or_else(|| {
        refuse(format!(
            "The text, {} characters, is not an Ed25519 public key in any spelling fiki reads: an \
             AID, raw base64url, a base58btc did:key, a did:peer:0, or an ssh-ed25519 line.",
            text.chars().count()
        ))
    })?;
    if public_key(&raw).is_none() {
        let on_curve = y_below_prime(&raw) && VerifyingKey::from_bytes(&raw).is_ok();
        return Err(refuse(if on_curve {
            "The key given is a point of small order, under which a signature can be forged for \
             any message, so no signature is checked against it."
                .into()
        } else {
            "The key given is not the canonical encoding of a point on the Ed25519 curve, so no \
             signature could be checked against it."
                .into()
        }));
    }
    Ok(aid_of(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// base58btc encoding, here only to show that decoding is its exact inverse.
    fn b58_encode(raw: &[u8]) -> String {
        let zeros = raw.iter().take_while(|b| **b == 0).count();
        let mut digits: Vec<u8> = Vec::new(); // little-endian base 58
        for byte in &raw[zeros..] {
            let mut carry = *byte as u32;
            for d in digits.iter_mut() {
                carry += *d as u32 * 256;
                *d = (carry % 58) as u8;
                carry /= 58;
            }
            while carry > 0 {
                digits.push((carry % 58) as u8);
                carry /= 58;
            }
        }
        let mut out = "1".repeat(zeros);
        out.extend(digits.iter().rev().map(|d| B58[*d as usize] as char));
        out
    }

    #[test]
    fn base58_decodes_every_string_to_the_one_byte_string_that_re_encodes_to_it() {
        // Exhaustive over every one- and two-character string, and every three-character string
        // that starts with "1" or the top digit, which is where an off-by-one in the leading-zero
        // rule or the carry would show.
        let mut texts: Vec<String> = Vec::new();
        for a in B58.iter() {
            texts.push((*a as char).to_string());
            for b in B58.iter() {
                texts.push(format!("{}{}", *a as char, *b as char));
                for c in *b"1z" {
                    texts.push(format!("{}{}{}", c as char, *a as char, *b as char));
                }
            }
        }
        texts.push("1111".into());
        texts.push("z".repeat(47));
        for text in texts {
            let raw = b58_decode(&text).unwrap();
            assert_eq!(b58_encode(&raw), text);
        }
        for raw in [
            vec![],
            vec![0],
            vec![0, 0, 1],
            vec![255; 34],
            (0u8..34).collect(),
        ] {
            assert_eq!(b58_decode(&b58_encode(&raw)).unwrap_or_default(), raw);
        }
    }

    #[test]
    fn base58_refuses_what_is_not_in_its_alphabet() {
        for text in ["", "0", "O", "I", "l", "+", "z0", "é"] {
            assert_eq!(b58_decode(text), None, "{text:?}");
        }
    }
}

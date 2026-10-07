//! Ed25519 keys, whose public half *is* the identifier (`this.i` @07wstqk7).
//!
//! The AID is the verifying key in CESR's `Ed25519N` encoding — a 44-character `B…` string. The
//! encoding is base64url over the raw 32 bytes with one leading pad byte, the first character then
//! replaced by the code: a few lines of arithmetic rather than a dependency, which is why fiki can
//! be ported to a language whose ecosystem has never heard of CESR.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::errors::{Error, Kind, Result};

// CESR's Ed25519N (non-transferable Ed25519 verification key). fiki decodes this code and no
// other: a decoder that handles one fixed-length code can only ever be narrower than a full CESR
// implementation, which is the safe direction for a differential.
const CODE: u8 = b'B';
const RAW_LEN: usize = 32;
const QB64_LEN: usize = 44;

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 with an explicit alphabet and no padding, written out rather than pulled in: the port
/// already takes three dependencies it cannot avoid, and this is thirty lines.
pub(crate) fn encode(raw: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(raw.len().div_ceil(3) * 4);
    for chunk in raw.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(alphabet[(n >> 18) as usize & 63] as char);
        out.push(alphabet[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(alphabet[(n >> 6) as usize & 63] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[n as usize & 63] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

pub(crate) fn decode(text: &str, alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    let mut lookup = [255u8; 256];
    for (i, ch) in alphabet.iter().enumerate() {
        lookup[*ch as usize] = i as u8;
    }
    let trimmed = text.trim_end_matches('=');
    // Padding may only appear at the end, and never more than two characters of it.
    if text.len() - trimmed.len() > 2 || trimmed.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() / 4 * 3);
    for chunk in trimmed.as_bytes().chunks(4) {
        let mut n: u32 = 0;
        for (i, ch) in chunk.iter().enumerate() {
            let v = lookup[*ch as usize];
            if v == 255 {
                return None;
            }
            n |= (v as u32) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

pub(crate) fn b64url(raw: &[u8]) -> String {
    encode(raw, URL_ALPHABET, false)
}

pub(crate) fn b64std(raw: &[u8]) -> String {
    encode(raw, STD_ALPHABET, true)
}

pub(crate) fn b64std_decode(text: &str) -> Option<Vec<u8>> {
    decode(text, STD_ALPHABET)
}

/// Render a raw 32-byte Ed25519 public key as a non-transferable AID.
pub fn to_aid(raw: &[u8]) -> String {
    let mut padded = [0u8; RAW_LEN + 1];
    padded[1..].copy_from_slice(raw);
    let mut aid = b64url(&padded);
    aid.replace_range(0..1, "B");
    aid
}

/// Recover the Ed25519 public key from a non-transferable AID.
pub fn verifying_key(aid: &str) -> Result<VerifyingKey> {
    if aid.len() != QB64_LEN || aid.as_bytes()[0] != CODE {
        return Err(Error::detailed(
            Kind::MalformedKey,
            "A non-transferable AID is 44 characters beginning with \"B\"; this one is not.",
            aid,
        ));
    }
    // Strict rather than lenient: "=" is inside base64's alphabet, so a lenient decoder would
    // accept a padded AID that decodes short, and a decoder is exactly the place a quiet shortfall
    // turns into somebody else's error.
    if !aid.bytes().all(|b| URL_ALPHABET.contains(&b)) {
        return Err(Error::detailed(
            Kind::MalformedKey,
            format!("The AID {aid} is not valid base64url."),
            aid,
        ));
    }
    let decoded = decode(&format!("A{}", &aid[1..]), URL_ALPHABET).ok_or_else(|| {
        Error::detailed(
            Kind::MalformedKey,
            format!("The AID {aid} is not valid base64url."),
            aid,
        )
    })?;
    let bytes: [u8; RAW_LEN] = decoded[1..].try_into().map_err(|_| {
        Error::detailed(
            Kind::MalformedKey,
            format!("The AID {aid} does not decode to a key."),
            aid,
        )
    })?;
    // The decode does not check the bits the code character overwrote: the second character's top
    // two bits land in the pad byte, so a non-zero pad would give one key two spellings. Only the
    // canonical one, the one to_aid produces, is the AID (bakobo/fiki#4).
    if to_aid(&bytes) != aid {
        return Err(Error::detailed(
            Kind::MalformedKey,
            format!("The AID {aid} is not the canonical spelling of its key."),
            aid,
        ));
    }
    public_key(&bytes).ok_or_else(|| {
        Error::detailed(
            Kind::MalformedKey,
            format!("The AID {aid} is not a usable Ed25519 public key."),
            aid,
        )
    })
}

/// The Ed25519 public key for 32 raw bytes, or `None` for bytes no signature should be checked
/// under (`this.i` @2t8xctts, @34qlc8r3, tick 27eo): anything that is not the canonical encoding of
/// an on-curve point, and any small-order point, which has no secret behind it that only one party
/// holds — under the identity point the signature 0x01 followed by 63 zero bytes verifies over any
/// message.
///
/// Three tests, each catching what the others cannot. y must be below the field prime, because
/// ed25519-dalek's decompression reduces y and so accepts its second spelling; decompression must
/// succeed, which is the curve test; and `is_weak` refuses a small-order point under any encoding
/// that decompresses, which includes x = 0 with the sign bit set, since x is zero only at y = 1
/// and y = -1, both small-order.
pub(crate) fn public_key(raw: &[u8; RAW_LEN]) -> Option<VerifyingKey> {
    if !y_below_prime(raw) {
        return None;
    }
    VerifyingKey::from_bytes(raw)
        .ok()
        .filter(|key| !key.is_weak())
}

/// Whether the little-endian y in an encoded point, sign bit cleared, is below p = 2^255 - 19.
/// Only 19 values are not: 0x7f, then thirty 0xff, then a low byte of 0xed or more.
fn y_below_prime(raw: &[u8; RAW_LEN]) -> bool {
    !(raw[31] & 0x7f == 0x7f && raw[1..31].iter().all(|b| *b == 0xff) && raw[0] >= 0xed)
}

/// An Ed25519 key pair whose public half is rendered as a non-transferable AID.
///
/// `Debug` prints the AID and nothing else. The AID is public by construction — it *is* the
/// verifying key — and the seed must never reach a log line by accident, which is exactly what a
/// derived `Debug` would arrange.
pub struct Key {
    signing: SigningKey,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("aid", &self.aid())
            .finish_non_exhaustive()
    }
}

impl Key {
    /// Create a key from fresh randomness.
    pub fn generate() -> Self {
        Key {
            signing: SigningKey::generate(&mut rand_core::OsRng),
        }
    }

    /// Recreate a key from its 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let bytes: [u8; RAW_LEN] = seed.try_into().map_err(|_| {
            Error::new(
                Kind::MalformedKey,
                format!("An Ed25519 seed is 32 bytes; this one is {}.", seed.len()),
            )
        })?;
        Ok(Key {
            signing: SigningKey::from_bytes(&bytes),
        })
    }

    /// The non-transferable AID: 44 characters, `B` prefixed, and also the verifying key.
    pub fn aid(&self) -> String {
        to_aid(self.signing.verifying_key().as_bytes())
    }

    /// The raw verifying key, base64url and unpadded — the RFC 8037 JWK "x" form (@7xrx5evg).
    pub fn keyid(&self) -> String {
        b64url(self.signing.verifying_key().as_bytes())
    }

    /// The 32-byte seed, for a caller that has to persist the key somewhere.
    pub fn seed(&self) -> [u8; RAW_LEN] {
        self.signing.to_bytes()
    }

    /// Sign bytes, returning the raw 64-byte Ed25519 signature.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing.sign(data).to_bytes()
    }
}

// The one-character codes whose 44-character qb64 carries 32 raw bytes behind one pad byte:
// Ed25519N (B), Ed25519 transferable (D), and Blake3-256 (E, the usual AID digest).
const SPELLED_CODES: &[u8] = b"BDE";

/// True when `keyid` is shaped like a B, D or E AID and is not its canonical spelling.
///
/// That is, 44 characters under one of those codes whose remaining 43 are not base64url, or which
/// decode with a non-zero pad byte and so name the same 32 bytes as another spelling. fiki checks
/// this before any resolver sees the keyid, so a resolver never has to (bakobo/fiki#4).
pub(crate) fn misspelled_aid(keyid: &str) -> bool {
    if keyid.len() != QB64_LEN || !SPELLED_CODES.contains(&keyid.as_bytes()[0]) {
        return false;
    }
    if !keyid.bytes().all(|b| URL_ALPHABET.contains(&b)) {
        return true;
    }
    // Forty-four base64url characters always decode to 33 bytes. Zeroing the pad byte and
    // re-encoding gives the one canonical spelling of those key bytes, behind any code.
    let mut decoded = decode(&format!("A{}", &keyid[1..]), URL_ALPHABET).unwrap_or_default();
    if let Some(pad) = decoded.first_mut() {
        *pad = 0;
    }
    b64url(&decoded).get(1..) != keyid.get(1..)
}

/// The raw key a keyid names in the RFC 8037 "x" form (@7xrx5evg), decoded strictly: exactly 43
/// base64url characters, unpadded, that re-encode to themselves. A lenient decoder ignores the
/// trailing bits, so a keyid that is not the key's own spelling could verify as whatever key it
/// happened to decode to.
pub(crate) fn raw_keyid(keyid: &str) -> Option<[u8; RAW_LEN]> {
    if keyid.len() != 43 || !keyid.bytes().all(|b| URL_ALPHABET.contains(&b)) {
        return None;
    }
    let raw: [u8; RAW_LEN] = decode(keyid, URL_ALPHABET)?.try_into().ok()?;
    (b64url(&raw) == keyid).then_some(raw)
}

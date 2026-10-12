//! Unencrypted OpenSSH Ed25519 private keys, for [`Key::from_openssh`](crate::Key::from_openssh)
//! (`this.i` @0mvgkwnl), and the two encodings an OpenSSH public line shares with them.

use crate::errors::{Error, Kind, Result};
use crate::keys::{b64std, b64std_decode};

const RAW_LEN: usize = 32;
const SSH_TYPE: &[u8] = b"ssh-ed25519";

/// Padded standard base64, or `None` unless `text` is the one canonical spelling of its bytes.
pub(crate) fn b64std_canonical(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 != 0 {
        return None;
    }
    let data = b64std_decode(text)?;
    (b64std(&data) == text).then_some(data)
}

/// RFC 4251 section 5 wire fields, refusing any length that overruns what is there.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn uint32(&mut self) -> Option<u32> {
        // Not split_first_chunk, which is newer than the crate's rust-version.
        if self.data.len() < 4 {
            return None;
        }
        let (head, rest) = self.data.split_at(4);
        self.data = rest;
        Some(u32::from_be_bytes([head[0], head[1], head[2], head[3]]))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let length = self.uint32()? as usize;
        if length > self.data.len() {
            return None;
        }
        let (value, rest) = self.data.split_at(length);
        self.data = rest;
        Some(value)
    }
}

/// The 32 raw bytes of an ssh-ed25519 public blob with nothing after them, or `None`.
pub(crate) fn ssh_public_blob(blob: &[u8]) -> Option<[u8; RAW_LEN]> {
    let mut reader = Reader { data: blob };
    if reader.string()? != SSH_TYPE {
        return None;
    }
    let raw = reader.string()?.try_into().ok()?;
    reader.data.is_empty().then_some(raw)
}

/// The most characters an armored private key may have, checked before anything is decoded.
pub(crate) const MAX_PRIVATE_CHARS: usize = 4096;

const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END: &str = "-----END OPENSSH PRIVATE KEY-----";
const MAGIC: &[u8] = b"openssh-key-v1\0";

fn refuse(reason: &str) -> Error {
    // No detail, and the reason never quotes the input: a private key must not reach a log.
    Error::new(
        Kind::MalformedKey,
        format!("The OpenSSH private key was refused: {reason}"),
    )
}

/// One line of an armored body: standard base64 characters, then at most two "=".
fn base64_line(line: &str) -> bool {
    let data = line.trim_end_matches('=');
    !line.is_empty()
        && line.len() - data.len() <= 2
        && data
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// The 32-byte Ed25519 seed in an unencrypted openssh-key-v1 private key.
pub(crate) fn read_openssh(text: &str) -> Result<[u8; RAW_LEN]> {
    // Bounded first, and the count itself stops one past the bound however long `text` is.
    if text.chars().nth(MAX_PRIVATE_CHARS).is_some() {
        return Err(refuse(&format!(
            "it is over {MAX_PRIVATE_CHARS} characters."
        )));
    }
    let lines: Vec<&str> = text
        .strip_suffix('\n')
        .unwrap_or(text)
        .split('\n')
        .collect();
    if lines.len() < 3 || lines[0] != BEGIN || lines[lines.len() - 1] != END {
        return Err(refuse(&format!(
            "it is not one \"{BEGIN}\" block with LF line endings and nothing around it."
        )));
    }
    let body = &lines[1..lines.len() - 1];
    if !body.iter().all(|line| base64_line(line)) {
        return Err(refuse("its body is not lines of standard base64."));
    }
    let blob = b64std_canonical(&body.concat())
        .ok_or_else(|| refuse("its body is not canonical standard base64."))?;
    let rest = blob
        .strip_prefix(MAGIC)
        .ok_or_else(|| refuse("it is not in the openssh-key-v1 format."))?;
    let mut reader = Reader { data: rest };
    let (cipher, kdf, kdfoptions) = (reader.string(), reader.string(), reader.string());
    if cipher.is_some_and(|c| c != b"none") {
        return Err(refuse(
            "it is encrypted under a passphrase, and fiki reads only unencrypted keys. Keep a \
             dedicated key for fiki rather than removing the passphrase from one used elsewhere.",
        ));
    }
    if cipher.is_none()
        || kdf != Some(b"none")
        || kdfoptions != Some(b"")
        || reader.uint32() != Some(1)
    {
        return Err(refuse(
            "its header is not that of exactly one unencrypted key.",
        ));
    }
    let raw = reader.string().and_then(ssh_public_blob);
    let private = reader.string();
    match (raw, private) {
        (Some(raw), Some(private)) if reader.data.is_empty() => private_section(private, &raw),
        _ => Err(refuse(
            "it is not exactly one ssh-ed25519 key with nothing after it.",
        )),
    }
}

/// The seed from the private section, after every consistency check it carries.
fn private_section(private: &[u8], raw: &[u8; RAW_LEN]) -> Result<[u8; RAW_LEN]> {
    let mut reader = Reader { data: private };
    let check = reader.uint32();
    if private.len() % 8 != 0 || check.is_none() || check != reader.uint32() {
        return Err(refuse(
            "its private section is misaligned or its check integers differ.",
        ));
    }
    let (ktype, inner, secret, comment) = (
        reader.string(),
        reader.string(),
        reader.string(),
        reader.string(),
    );
    let secret = match secret {
        Some(secret)
            if ktype == Some(SSH_TYPE)
                && inner == Some(&raw[..])
                && secret.len() == 2 * RAW_LEN =>
        {
            secret
        }
        _ => {
            return Err(refuse(
                "its private section does not hold the key its public section names.",
            ))
        }
    };
    let mut seed = [0u8; RAW_LEN];
    seed.copy_from_slice(&secret[..RAW_LEN]);
    let derived = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    if secret[RAW_LEN..] != raw[..] || derived.as_bytes() != raw {
        return Err(refuse(
            "its seed does not derive the public key it is stored with.",
        ));
    }
    if !comment.is_some_and(|c| c.iter().all(|b| (0x20..=0x7e).contains(b))) {
        return Err(refuse("its comment is not printable ASCII."));
    }
    let padding = reader.data;
    if padding.len() >= 8 || !padding.iter().zip(1u8..).all(|(b, n)| *b == n) {
        return Err(refuse(
            "its padding is not 1, 2, 3, ... to the next eight-byte boundary.",
        ));
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(out: &mut Vec<u8>, value: &[u8]) {
        out.extend((value.len() as u32).to_be_bytes());
        out.extend(value);
    }

    /// A private section as ssh-keygen lays one out, with `comment` written raw so that a test can
    /// make its length overrun what follows.
    fn section(comment: &[u8]) -> (Vec<u8>, [u8; RAW_LEN]) {
        let seed = [7u8; RAW_LEN];
        let raw = *ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .as_bytes();
        let mut out = [0x0102_0304u32.to_be_bytes(); 2].concat();
        string(&mut out, SSH_TYPE);
        string(&mut out, &raw);
        string(&mut out, &[seed, raw].concat());
        out.extend(comment);
        let pad = (8 - out.len() % 8) % 8;
        out.extend(1..=pad as u8);
        (out, raw)
    }

    #[test]
    fn a_private_section_loads_and_one_whose_comment_overruns_it_is_refused() {
        let mut comment = Vec::new();
        string(&mut comment, b"fiki");
        let (good, raw) = section(&comment);
        assert_eq!(private_section(&good, &raw).unwrap(), [7u8; RAW_LEN]);

        // A comment length that runs past the end of the section, so the comment is never read.
        let (overrun, raw) = section(&64u32.to_be_bytes());
        let error = private_section(&overrun, &raw).unwrap_err();
        assert_eq!(error.kind, Kind::MalformedKey);
        assert!(error.message.contains("comment"), "{error}");
        assert_eq!(error.detail, None);
    }
}

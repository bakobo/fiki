//! Unencrypted OpenSSH Ed25519 private keys, for [`Key::from_openssh`](crate::Key::from_openssh)
//! (`this.i` @0mvgkwnl), and the two encodings an OpenSSH public line shares with them.

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

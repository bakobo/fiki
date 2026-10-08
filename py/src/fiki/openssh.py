"""Unencrypted OpenSSH Ed25519 private keys, for :meth:`fiki.Key.from_openssh` (``this.i`` @0mvgkwnl).

Kept apart from :mod:`fiki.formats`, and importing nothing from :mod:`fiki.keys`, so that keys can
use it without an import cycle. It needs nothing from keys: the seed it returns derives its own
public key, and a seed always derives a point of prime order, so the small-order refusal of
@37wdchu5 cannot fire here once the stored public key is checked against the derived one.
"""

from __future__ import annotations

import base64
import re
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .errors import MalformedKey

# Checked before anything is decoded (input-handling standard: size, then shape, then meaning).
MAX_PRIVATE_CHARS = 4096

_RAW_LEN = 32
_SSH_TYPE = b"ssh-ed25519"
_B64STD = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
_END = "-----END OPENSSH PRIVATE KEY-----"
_MAGIC = b"openssh-key-v1\x00"


def _b64std(text: str) -> bytes | None:
    """Padded standard base64, or None unless ``text`` is the one canonical spelling."""
    if not _B64STD.fullmatch(text) or len(text) % 4:
        return None
    data = base64.b64decode(text, validate=True)
    return data if base64.b64encode(data).decode("ascii") == text else None


class _Reader:
    """RFC 4251 section 5 wire fields, refusing any length that overruns what is there."""

    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def uint32(self) -> int | None:
        if len(self.data) - self.pos < 4:
            return None
        (value,) = struct.unpack_from(">I", self.data, self.pos)
        self.pos += 4
        return value

    def string(self) -> bytes | None:
        length = self.uint32()
        if length is None or length > len(self.data) - self.pos:
            return None
        value = self.data[self.pos:self.pos + length]
        self.pos += length
        return value

    def rest(self) -> bytes:
        return self.data[self.pos:]


def _ssh_public_blob(blob: bytes) -> bytes | None:
    """The 32 raw bytes of an ssh-ed25519 public blob with nothing after them, or None."""
    reader = _Reader(blob)
    if reader.string() != _SSH_TYPE:
        return None
    raw = reader.string()
    return raw if raw is not None and len(raw) == _RAW_LEN and not reader.rest() else None


def _refuse_private(reason: str) -> MalformedKey:
    # keyid is empty and the reason never quotes the input: a private key must not reach a log.
    return MalformedKey(f"The OpenSSH private key was refused: {reason}", keyid="")


def read_openssh(text: str) -> bytes:
    """The 32-byte Ed25519 seed in an unencrypted openssh-key-v1 private key.

    The text is the armored key as ssh-keygen writes it, LF line endings, with or without the
    final newline. The key must be the only one in the file, its check integers must agree, its
    padding must be 1, 2, 3, ..., and its public key must match in both places it is stored and
    must be the one its seed derives. Raises :class:`~fiki.errors.MalformedKey` otherwise, and
    the error never carries any part of the key.
    """
    if not isinstance(text, str):
        # A caller's mistake, such as a key read in binary mode, reported in Python's idiom so
        # that catching fiki's refusals cannot swallow it (docs/user-guide.md, "Handling errors").
        raise TypeError(f"An OpenSSH private key is text (str), not {type(text).__name__}.")
    if len(text) > MAX_PRIVATE_CHARS:
        raise _refuse_private(f"it is over {MAX_PRIVATE_CHARS} characters.")
    lines = text.removesuffix("\n").split("\n")
    if len(lines) < 3 or lines[0] != _BEGIN or lines[-1] != _END:
        raise _refuse_private(
            f'it is not one "{_BEGIN}" block with LF line endings and nothing around it.'
        )
    body = lines[1:-1]
    if any(not line or not _B64STD.fullmatch(line) for line in body):
        raise _refuse_private("its body is not lines of standard base64.")
    blob = _b64std("".join(body))
    if blob is None:
        raise _refuse_private("its body is not canonical standard base64.")
    if not blob.startswith(_MAGIC):
        raise _refuse_private("it is not in the openssh-key-v1 format.")
    reader = _Reader(blob[len(_MAGIC):])
    cipher, kdf, kdfoptions = reader.string(), reader.string(), reader.string()
    if cipher not in (b"none", None):
        raise _refuse_private(
            "it is encrypted under a passphrase, and fiki reads only unencrypted keys. Keep a "
            "dedicated key for fiki rather than removing the passphrase from one used elsewhere."
        )
    if cipher is None or kdf != b"none" or kdfoptions != b"" or reader.uint32() != 1:
        raise _refuse_private("its header is not that of exactly one unencrypted key.")
    public = reader.string()
    raw = None if public is None else _ssh_public_blob(public)
    private = reader.string()
    if raw is None or private is None or reader.rest():
        raise _refuse_private("it is not exactly one ssh-ed25519 key with nothing after it.")
    return _private_section(private, raw)


def _private_section(private: bytes, raw: bytes) -> bytes:
    """The seed from the private section, after every consistency check it carries."""
    reader = _Reader(private)
    check = reader.uint32()
    if len(private) % 8 or check is None or check != reader.uint32():
        raise _refuse_private("its private section is misaligned or its check integers differ.")
    ktype, inner, secret, comment = reader.string(), reader.string(), reader.string(), reader.string()
    if ktype != _SSH_TYPE or inner != raw or secret is None or len(secret) != 2 * _RAW_LEN:
        raise _refuse_private("its private section does not hold the key its public section names.")
    seed = secret[:_RAW_LEN]
    derived = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    if secret[_RAW_LEN:] != raw or derived != raw:
        raise _refuse_private("its seed does not derive the public key it is stored with.")
    padding = reader.rest()
    if comment is None or any(b < 0x20 or b > 0x7E for b in comment):
        raise _refuse_private("its comment is not printable ASCII.")
    if len(padding) >= 8 or padding != bytes(range(1, len(padding) + 1)):
        raise _refuse_private("its padding is not 1, 2, 3, ... to the next eight-byte boundary.")
    return seed

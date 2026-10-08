"""Other spellings of an Ed25519 key, read at the edge of the API (``this.i`` @0mvgkwnl).

:func:`aid_from` turns a public key spelled as an AID, as raw base64url (the wire keyid of
@7xrx5evg, also a JWK's ``x``), as a did:key, as a did:peer with numalgo 0, or as an OpenSSH public
line into the canonical AID. :func:`read_openssh` reads the seed out of an unencrypted
openssh-key-v1 private key, for :meth:`fiki.Key.from_openssh`.

Nothing here touches a request. A verifier calls :func:`aid_from` when it loads its registrations,
so a bad one fails at configuration time rather than on a live request, and ``expected_aid`` stays
a single spelling. Every spelling has exactly one accepted form: each decoder below re-encodes
what it decoded and refuses a mismatch, so no key has two spellings that both pass. Every decoded
key then goes through :func:`fiki.keys.public_key`, so no spelling is a way around the small-order
refusal (@37wdchu5).
"""

from __future__ import annotations

import base64
import re
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .errors import MalformedKey
from .keys import public_key, to_aid, verifying_key

# Checked before anything is decoded, so nothing below ever sees more than this (input-handling
# standard: size, then shape, then meaning). An OpenSSH public line's comment is the only part
# of any spelling that varies much, and 1024 characters leaves it ample room.
MAX_PUBLIC_CHARS = 1024
MAX_PRIVATE_CHARS = 4096

_RAW_LEN = 32
_AID_LEN = 44
_RAW_B64URL_LEN = 43
_ED25519_PUB = b"\xed\x01"  # multicodec ed25519-pub, 0xed as an unsigned varint
_SSH_TYPE = b"ssh-ed25519"
# A multibase value over 34 bytes is at most 47 base58 or 46 base64url characters; anything
# longer cannot be an Ed25519 did:key, and refusing it first keeps base58's big-integer
# arithmetic to a fixed size.
_MAX_MULTIBASE = 48

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_B64STD = re.compile(r"[A-Za-z0-9+/]*={0,2}")
# "ssh-ed25519", one space, the blob, and optionally one space and a printable-ASCII comment.
_SSH_LINE = re.compile(r"ssh-ed25519 ([A-Za-z0-9+/=]+)(?: ([\x20-\x7e]+))?")

_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
_END = "-----END OPENSSH PRIVATE KEY-----"
_MAGIC = b"openssh-key-v1\x00"


def _b64url(text: str) -> bytes | None:
    """Unpadded base64url, or None unless ``text`` is the one canonical spelling of its bytes."""
    if not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        return None
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    return data if base64.urlsafe_b64encode(data).decode("ascii").rstrip("=") == text else None


def _b64std(text: str) -> bytes | None:
    """Padded standard base64, or None unless ``text`` is the one canonical spelling."""
    if not _B64STD.fullmatch(text) or len(text) % 4:
        return None
    data = base64.b64decode(text, validate=True)
    return data if base64.b64encode(data).decode("ascii") == text else None


def _b58(text: str) -> bytes | None:
    """base58btc, or None. Leading "1"s are zero bytes, so every string has exactly one meaning."""
    if not text or any(c not in _B58_INDEX for c in text):
        return None
    number = 0
    for c in text:
        number = number * 58 + _B58_INDEX[c]
    zeros = len(text) - len(text.lstrip("1"))
    return b"\x00" * zeros + number.to_bytes((number.bit_length() + 7) // 8, "big")


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


def _multibase_ed25519(value: str) -> bytes | None:
    """The raw key under a did:key multibase value, base58btc ("z") or base64url ("u")."""
    if len(value) > _MAX_MULTIBASE:
        return None
    decoded = {"z": _b58, "u": _b64url}.get(value[:1], lambda _: None)(value[1:])
    if decoded is None or len(decoded) != len(_ED25519_PUB) + _RAW_LEN:
        return None
    return decoded[2:] if decoded[:2] == _ED25519_PUB else None


def _raw_of(text: str) -> bytes | None:
    """The raw key ``text`` spells, by its shape, or None for a shape fiki does not read."""
    if len(text) == _RAW_B64URL_LEN:
        return _b64url(text)
    if text.startswith("did:key:"):
        return _multibase_ed25519(text[len("did:key:"):])
    if text.startswith("did:peer:0"):
        return _multibase_ed25519(text[len("did:peer:0"):])
    line = _SSH_LINE.fullmatch(text)
    if line:
        blob = _b64std(line.group(1))
        return None if blob is None else _ssh_public_blob(blob)
    return None


def aid_from(text: str) -> str:
    """The canonical AID of the Ed25519 public key ``text`` spells.

    ``text`` is an AID, the raw key as 43 characters of unpadded base64url (a JWK's ``x``), a
    did:key, a did:peer with numalgo 0, or an OpenSSH public line — ``ssh-ed25519``, one space,
    the blob, and optionally one space and a printable-ASCII comment. Length, not the first
    character, tells raw from AID: 43 against 44. Nothing around ``text`` is stripped; that is the
    caller's, so that one input never has two readings.

    Raises :class:`~fiki.errors.MalformedKey` for anything else, including a transferable or
    digest AID, whose key is not the identifier's to give.
    """
    if len(text) > MAX_PUBLIC_CHARS:
        raise MalformedKey(
            f"A public key is at most {MAX_PUBLIC_CHARS} characters in any spelling fiki reads; "
            f"this one is {len(text)}.",
            keyid="",
        )
    if len(text) == _AID_LEN and text[:1] in "DE":
        raise MalformedKey(
            f'"{text}" is a transferable or digest AID, whose current key is not recoverable from '
            "the identifier; resolve it to a key first.",
            keyid=text,
        )
    if len(text) == _AID_LEN and text[:1] == "B":
        verifying_key(text)
        return text
    raw = _raw_of(text)
    if raw is None:
        raise MalformedKey(
            f'"{text}" is not an Ed25519 public key in any spelling fiki reads: an AID, raw '
            "base64url, a did:key, a did:peer:0, or an ssh-ed25519 line.",
            keyid=text,
        )
    public_key(raw, text)
    return to_aid(raw)


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
    seed = _private_section(private, raw)
    public_key(raw, "")
    return seed


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

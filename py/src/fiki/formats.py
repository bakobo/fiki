"""Other spellings of an Ed25519 key, read at the edge of the API (``this.i`` @0mvgkwnl).

:func:`aid_from` turns a public key spelled as an AID, as raw base64url (the wire keyid of
@7xrx5evg, also a JWK's ``x``), as a base58btc did:key, as a did:peer with numalgo 0, or as an
OpenSSH public line into the canonical AID. The OpenSSH private-key reader is :mod:`fiki.openssh`.

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

from .errors import MalformedKey
from .keys import public_key, to_aid
from .openssh import _b64std, _ssh_public_blob

# Checked before anything is decoded, so nothing below ever sees more than this (input-handling
# standard: size, then shape, then meaning). An OpenSSH public line's comment is the only part
# of any spelling that varies much, and 1024 characters leaves it ample room.
MAX_PUBLIC_CHARS = 1024

_RAW_LEN = 32
_AID_LEN = 44
_RAW_B64URL_LEN = 43
_ED25519_PUB = b"\xed\x01"  # multicodec ed25519-pub, 0xed as an unsigned varint
# A base58btc value over 34 bytes is at most 47 characters after the "z"; anything longer cannot
# be an Ed25519 did:key, and refusing it first keeps base58's big-integer arithmetic to a fixed size.
_MAX_MULTIBASE = 48

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
# "ssh-ed25519", one space, the blob, and optionally one space and a printable-ASCII comment that
# neither begins nor ends with a space, so that no whitespace around any field is ever ignored.
_SSH_LINE = re.compile(r"ssh-ed25519 ([A-Za-z0-9+/=]+)(?: ([\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?))?")



def _b64url(text: str) -> bytes | None:
    """Unpadded base64url, or None unless ``text`` is the one canonical spelling of its bytes."""
    if not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        return None
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    return data if base64.urlsafe_b64encode(data).decode("ascii").rstrip("=") == text else None


def _b58(text: str) -> bytes | None:
    """base58btc, or None. Leading "1"s are zero bytes, so every string has exactly one meaning."""
    if not text or any(c not in _B58_INDEX for c in text):
        return None
    number = 0
    for c in text:
        number = number * 58 + _B58_INDEX[c]
    zeros = len(text) - len(text.lstrip("1"))
    return b"\x00" * zeros + number.to_bytes((number.bit_length() + 7) // 8, "big")


def _multibase_ed25519(value: str) -> bytes | None:
    """The raw key under a did:key multibase value, which is base58btc ("z") only.

    The did:key ABNF also admits base64url ("u"), but the spec's resolution algorithm requires
    the value to "begin with the letter `z`" or raise invalidDid, and the peer DID ABNF has
    transform = "z". Reading "u" too would give every key two DIDs.
    """
    if len(value) > _MAX_MULTIBASE or value[:1] != "z":
        return None
    decoded = _b58(value[1:])
    if decoded is None or len(decoded) != len(_ED25519_PUB) + _RAW_LEN:
        return None
    return decoded[2:] if decoded[:2] == _ED25519_PUB else None


def _aid_body(text: str) -> bytes | None:
    """The 32 bytes under a 44-character B, D or E AID, or None unless it is spelled canonically.

    An AID is base64url over a zero pad byte and the bytes, with the pad's character replaced by
    the code; only the spelling to_aid produces, code aside, is an AID (bakobo/fiki#4).
    """
    if len(text) != _AID_LEN or text[:1] not in "BDE":
        return None
    decoded = _b64url("A" + text[1:])
    return decoded[1:] if decoded is not None and to_aid(decoded[1:])[1:] == text[1:] else None


def _raw_of(text: str) -> bytes | None:
    """The raw key ``text`` spells, by its shape, or None for a shape fiki does not read."""
    if len(text) == _AID_LEN and text[:1] == "B":
        return _aid_body(text)
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
    the blob, and optionally one space and a printable-ASCII comment that neither begins nor ends
    with a space. Length, not the first character, tells raw from AID: 43 against 44. Nothing
    around ``text`` is stripped; that is the caller's, so that one input never has two readings.

    Raises :class:`~fiki.errors.MalformedKey` for anything else, including a transferable or
    digest AID, whose key is not the identifier's to give. The error never quotes ``text`` and its
    ``keyid`` is empty, because what is handed here by mistake can be a private key: the ``.key``
    file instead of the ``.pub``, or a seed, which in base64url is 43 characters like a raw key.
    """
    if not isinstance(text, str):
        # A caller's mistake, reported in Python's idiom so that catching fiki's refusals cannot
        # swallow it (docs/user-guide.md, "Handling errors").
        raise TypeError(f"A public key is text (str), not {type(text).__name__}.")
    if len(text) > MAX_PUBLIC_CHARS:
        raise MalformedKey(
            f"A public key is at most {MAX_PUBLIC_CHARS} characters in any spelling fiki reads; "
            f"this one is {len(text)}.",
            keyid="",
        )
    # Shape before meaning: only a canonically spelled D or E AID is told what it is.
    if text[:1] in "DE" and _aid_body(text) is not None:
        raise MalformedKey(
            "The text is a transferable or digest AID, whose current key is not recoverable from "
            "the identifier; resolve it to a key first.",
            keyid="",
        )
    raw = _raw_of(text)
    if raw is None:
        raise MalformedKey(
            f"The text, {len(text)} characters, is not an Ed25519 public key in any spelling fiki "
            "reads: an AID, raw base64url, a base58btc did:key, a did:peer:0, or an ssh-ed25519 "
            "line.",
            keyid="",
        )
    public_key(raw, "")
    return to_aid(raw)

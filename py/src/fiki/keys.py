"""Ed25519 keys, whose public half *is* the identifier (``this.i`` @07wstqk7).

A :class:`Key`'s ``aid`` is its verifying key in CESR's ``Ed25519N`` encoding — a 44-character
``B…`` string. Non-transferable is the whole point: the key is recoverable from the identifier
alone, so a verifier resolves nothing and fetches nothing.

The encoding is base64url over the raw 32 bytes with one leading pad byte, the first character
then replaced by the code. That is a few lines of arithmetic rather than a dependency, which is why
fiki can be ported to a language whose ecosystem has never heard of CESR.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._text import shown
from .errors import MalformedKey
from .openssh import read_openssh

# CESR's Ed25519N (non-transferable Ed25519 verification key). fiki decodes this code and no
# other, deliberately: a parser that handles one fixed-length code can only ever be narrower than
# a full CESR implementation, which is the safe direction for a differential.
_CODE = "B"
_RAW_LEN = 32
# 32 raw bytes need one leading pad byte to reach a multiple of 3, giving 33 bytes and so 44
# base64url characters with no "=" padding. The pad byte's character is then overwritten by _CODE.
_PAD = b"\x00"
_QB64_LEN = 44


# Curve25519's field prime and the twisted Edwards constant d of RFC 8032 section 5.1.
_P = 2**255 - 19
_D = -121665 * pow(121666, -1, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _decode_point(raw: bytes) -> tuple[int, int] | None:
    """RFC 8032 section 5.1.3: the point ``raw`` encodes, or None where that procedure fails.

    It fails for y at or above p, for a y with no x on the curve, and for the sign bit set where
    x is 0, which are exactly the encodings that are not a canonical on-curve point.
    """
    y = int.from_bytes(raw, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _P:
        return None
    u, v = (y * y - 1) % _P, (_D * y * y + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    if v * x * x % _P == (-u) % _P:
        x = x * _SQRT_M1 % _P
    if v * x * x % _P != u or (x == 0 and sign):
        return None
    return (_P - x if x & 1 != sign else x), y


def _small_order(x: int, y: int) -> bool:
    """True when [8]P is the identity: three doublings by RFC 8032 section 5.1.4's formula."""
    X, Y, Z = x, y, 1
    for _ in range(3):
        a, b, c = X * X, Y * Y, 2 * Z * Z
        h = a + b
        e, g = h - (X + Y) ** 2, a - b
        f = c + g
        X, Y, Z = e * f % _P, g * h % _P, f * g % _P
    return X == 0 and Y == Z


# The order of Ed25519's prime-order subgroup, RFC 8032 section 5.1's L.
_L = 2**252 + 27742317777372353535851937790883648493


def _add(a, b):
    """RFC 8032 section 5.1.4's addition, on points in extended coordinates (X, Y, Z, T)."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    e1, h1 = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    c, d = t1 * 2 * _D * t2 % _P, z1 * 2 * z2 % _P
    e, f, g, h = h1 - e1, d - c, d + c, h1 + e1
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _prime_order(x: int, y: int) -> bool:
    """True when [L]P is the identity, so P lies in the prime-order subgroup (@37rktct3).

    A point of small order is not caught here, since the identity is one; ``_small_order`` runs
    first. What this adds is the mixed-order point, a subgroup point plus a torsion component,
    which libsodium's crypto_core_ed25519_is_valid_point refuses and keripy follows.
    """
    total, step, n = (0, 1, 1, 0), (x, y, 1, x * y % _P), _L
    while n:
        if n & 1:
            total = _add(total, step)
        step, n = _add(step, step), n >> 1
    return total[0] == 0 and total[1] == total[2]


def public_key(raw: bytes, keyid: str, *, subgroup: bool = False) -> Ed25519PublicKey:
    """The Ed25519 public key ``raw`` encodes, refused unless it is one an honest signer holds.

    Raises :class:`~fiki.errors.MalformedKey`, before any signature is examined, for an encoding
    that is not a canonical on-curve point or for a point of small order (@37wdchu5). Under the
    identity point, the key 0x01 followed by 31 zero bytes, a signature of 0x01 followed by 63
    zero bytes verifies over any message, and OpenSSL accepts it. With ``subgroup``, which is how
    a key named by an AID is read (KERI profile R1, @37rktct3), a point outside the prime-order
    subgroup is refused too; fiki's own raw keyid accepts one (@5r75ff4m).
    """
    # An empty keyid names no one, for a caller that must not echo what it was given (@0mvgkwnl).
    subject = f"The key for {shown(keyid)}" if keyid else "The key given"
    # First, on every path: the decoding below reads any length as an integer, and cryptography
    # would refuse a wrong one with a ValueError from outside fiki's taxonomy.
    if len(raw) != _RAW_LEN:
        raise MalformedKey(
            f"{subject} is {len(raw)} bytes, and an Ed25519 public key is {_RAW_LEN}.",
            keyid=keyid,
        )
    point = _decode_point(raw)
    if point is None:
        raise MalformedKey(
            f"{subject} is not the canonical encoding of a point on the Ed25519 curve, so no "
            "signature could be checked against it.",
            keyid=keyid,
        )
    if _small_order(*point):
        raise MalformedKey(
            f"{subject} is a point of small order, under which a signature can be forged for "
            "any message, so no signature is checked against it.",
            keyid=keyid,
        )
    if subgroup and not _prime_order(*point):
        raise MalformedKey(
            f"{subject} is a point of mixed order, outside the prime-order subgroup every honest "
            "key lies in, so no signature is checked against it.",
            keyid=keyid,
        )
    return Ed25519PublicKey.from_public_bytes(raw)


def to_aid(raw: bytes) -> str:
    """Render a raw 32-byte Ed25519 public key as a non-transferable AID."""
    return _CODE + base64.urlsafe_b64encode(_PAD + raw).decode("ascii")[1:]


class Key:
    """An Ed25519 key pair whose public half is rendered as a non-transferable AID."""

    def __init__(self, private_key: Ed25519PrivateKey, seed: bytes):
        self._private_key = private_key
        self._seed = seed

    @classmethod
    def generate(cls) -> Key:
        """Create a key from a fresh random seed."""
        private_key = Ed25519PrivateKey.generate()
        return cls(private_key, private_key.private_bytes_raw())

    @classmethod
    def from_seed(cls, seed: bytes) -> Key:
        """Recreate a key from its 32-byte Ed25519 seed."""
        if len(seed) != _RAW_LEN:
            raise MalformedKey(
                f"An Ed25519 seed is {_RAW_LEN} bytes; this one is {len(seed)}.", keyid=""
            )
        return cls(Ed25519PrivateKey.from_private_bytes(seed), bytes(seed))

    @classmethod
    def from_openssh(cls, text: str) -> Key:
        """Load an unencrypted OpenSSH Ed25519 private key, as ssh-keygen writes it (@0mvgkwnl).

        Use a key dedicated to fiki and never loaded into ssh-agent. Signatures do not cross
        between protocols -- every base sign_request and sign_response build begins with a double
        quote, SSH user authentication signs data beginning with a length-prefixed session
        identifier (RFC 4252 section 7), and SSHSIG signs data beginning "SSHSIG" -- but an agent
        signs whatever bytes it is asked to, so anyone able to use a forwarded agent could sign
        fiki requests with a login key. The separation is a property of sign_request, not of the
        key: Key.sign signs any bytes.
        """
        return cls.from_seed(read_openssh(text))

    @property
    def aid(self) -> str:
        """The non-transferable AID — 44 characters, ``B`` prefixed, also the verifying key."""
        return to_aid(self._private_key.public_key().public_bytes_raw())

    @property
    def seed(self) -> bytes:
        """The 32-byte seed, for a caller that has to persist the key somewhere."""
        return self._seed

    def sign(self, data: bytes) -> bytes:
        """Sign bytes, returning the raw 64-byte Ed25519 signature.

        Raw rather than CESR-qualified, because RFC 9421 carries the signature as an RFC 8941 byte
        sequence and qualifying it here would only mean unqualifying it at the header.
        """
        return self._private_key.sign(data)


# keripy's PreDex, the prefix derivation codes an AID may carry, with the raw size each encodes
# (@37rktct3). fiki reads none of them but B; it needs the table only to say whether a keyid is a
# well-formed AID, which the KERI profile's R1 makes the verifier's job before any key store is asked.
_PREFIX_CODES = {
    "B": 32, "D": 32, "E": 32, "F": 32, "G": 32, "H": 32, "I": 32,
    "0D": 64, "0E": 64, "0F": 64, "0G": 64,
    "1AAA": 33, "1AAB": 33, "1AAI": 33, "1AAJ": 33,
    "1AAC": 57, "1AAD": 57,
    "1AAE": 114,
}

# The non-transferable codes other than B: secp256k1, Ed448 and secp256r1 keys, whose algorithm
# the profile does not support.
OTHER_NON_TRANSFERABLE = frozenset({"1AAA", "1AAC", "1AAI"})


def aid_code(keyid: str) -> str | None:
    """The PreDex code of ``keyid`` when it is a well-formed AID, else None (@7w7nv94j, @37rktct3).

    The code is one, two or four characters by its first character, as CESR sizes it; the raw
    bytes behind it are padded with zero bytes to a multiple of three, base64url-encoded, and the
    code written over the characters the padding became. Well formed means exactly that spelling:
    the right length, base64url throughout, and zero pad bits, so that re-encoding gives back the
    keyid. fiki checks this before any resolver sees a keyid, so a resolver only ever answers
    about key state.
    """
    size = 1 if keyid[:1].isalpha() else 2 if keyid[:1] == "0" else 4
    code = keyid[:size]
    length = _PREFIX_CODES.get(code)
    if length is None:
        return None
    pad = (3 - length % 3) % 3
    if len(keyid) != (pad + length) * 4 // 3 + (size - pad):
        return None
    try:
        decoded = base64.b64decode("A" * pad + keyid[size:], altchars=b"-_", validate=True)
    except ValueError:  # binascii.Error, or non-ASCII input, which base64 refuses as ValueError
        return None
    spelled = base64.urlsafe_b64encode(bytes(pad) + decoded[pad:]).decode("ascii")[pad:]
    return code if code + spelled == keyid else None


def well_formed_aid(keyid: str) -> bool:
    """True when ``keyid`` is a well-formed AID under the KERI vectors' keys_rule."""
    return aid_code(keyid) is not None


def aid_key(keyid: str) -> Ed25519PublicKey:
    """The key a well-formed B keyid carries, read as an AID's key: in the prime-order subgroup."""
    return public_key(base64.urlsafe_b64decode("A" + keyid[1:])[1:], keyid, subgroup=True)


def verifying_key(aid: str) -> Ed25519PublicKey:
    """Recover the Ed25519 public key from a non-transferable AID.

    Raises :class:`~fiki.errors.MalformedKey` for anything that is not a 44-character ``B…``
    string over the base64url alphabet, and for a key :func:`public_key` refuses.
    """
    if len(aid) != _QB64_LEN or not aid.startswith(_CODE):
        raise MalformedKey(
            f"A non-transferable AID is {_QB64_LEN} characters beginning with "
            f'"{_CODE}"; this one is {len(aid)} characters and begins with '
            f"{shown(aid[:1])}.",
            keyid=aid,
        )
    # validate=True rather than the default: without it, characters outside the alphabet are
    # silently DISCARDED, so a 44-character string of the right shape can decode to fewer bytes
    # than a key and surface as a cryptography ValueError from outside fiki's taxonomy. The
    # length assertion afterwards is belt to that suspenders — a decoder is exactly the place a
    # quiet shortfall turns into someone else's exception.
    # ValueError rather than binascii.Error: a non-ASCII character is refused by base64 before
    # any alphabet check, as a plain ValueError from outside fiki's taxonomy (tick 7wap).
    try:
        decoded = base64.b64decode("A" + aid[1:], altchars=b"-_", validate=True)
    except ValueError as ex:
        raise MalformedKey(f"The AID {shown(aid)} is not valid base64url.", keyid=aid) from ex
    if len(decoded) != len(_PAD) + _RAW_LEN:
        raise MalformedKey(
            f"The AID {shown(aid)} does not decode to a {_RAW_LEN}-byte key.", keyid=aid
        )
    # validate=True does not check the bits the code character overwrote: the second
    # character's top two bits land in the pad byte, so a non-zero pad would give one key two
    # spellings. Only the canonical one, the one to_aid produces, is the AID (bakobo/fiki#4).
    if to_aid(decoded[len(_PAD):]) != aid:
        raise MalformedKey(f"The AID {shown(aid)} is not the canonical spelling of its key.", keyid=aid)
    return public_key(decoded[len(_PAD):], aid)

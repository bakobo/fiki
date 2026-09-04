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
import binascii

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import MalformedKey

# CESR's Ed25519N (non-transferable Ed25519 verification key). fiki decodes this code and no
# other, deliberately: a parser that handles one fixed-length code can only ever be narrower than
# a full CESR implementation, which is the safe direction for a differential.
_CODE = "B"
_RAW_LEN = 32
# 32 raw bytes need one leading pad byte to reach a multiple of 3, giving 33 bytes and so 44
# base64url characters with no "=" padding. The pad byte's character is then overwritten by _CODE.
_PAD = b"\x00"
_QB64_LEN = 44


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


def verifying_key(aid: str) -> Ed25519PublicKey:
    """Recover the Ed25519 public key from a non-transferable AID.

    Raises :class:`~fiki.errors.MalformedKey` for anything that is not a 44-character ``B…``
    string over the base64url alphabet.
    """
    if len(aid) != _QB64_LEN or not aid.startswith(_CODE):
        raise MalformedKey(
            f"A non-transferable AID is {_QB64_LEN} characters beginning with "
            f'"{_CODE}"; this one is {len(aid)} characters and begins with '
            f'"{aid[:1]}".',
            keyid=aid,
        )
    # validate=True rather than the default: without it, characters outside the alphabet are
    # silently DISCARDED, so a 44-character string of the right shape can decode to fewer bytes
    # than a key and surface as a cryptography ValueError from outside fiki's taxonomy. The
    # length assertion afterwards is belt to that suspenders — a decoder is exactly the place a
    # quiet shortfall turns into someone else's exception.
    try:
        decoded = base64.b64decode("A" + aid[1:], altchars=b"-_", validate=True)
    except binascii.Error as ex:
        raise MalformedKey(f'The AID "{aid}" is not valid base64url.', keyid=aid) from ex
    if len(decoded) != len(_PAD) + _RAW_LEN:
        raise MalformedKey(
            f'The AID "{aid}" does not decode to a {_RAW_LEN}-byte key.', keyid=aid
        )
    return Ed25519PublicKey.from_public_bytes(decoded[len(_PAD):])

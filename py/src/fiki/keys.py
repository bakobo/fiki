"""Ed25519 keys, whose public half *is* the identifier (``this.i`` @07wstqk7).

A :class:`Key`'s ``aid`` is its verifying key in CESR's ``Ed25519N`` encoding — a 44-character
``B…`` string. Non-transferable is the whole point: the key is recoverable from the identifier
alone, so a verifier resolves nothing and fetches nothing.

The encoding is base64url over the raw 32 bytes with one leading pad byte, the first character
then replaced by the code. That is 40 lines of arithmetic rather than a dependency, which is why
fiki can be ported to a language whose ecosystem has never heard of CESR.
"""

from __future__ import annotations


class Key:
    """An Ed25519 key pair whose public half is rendered as a non-transferable AID."""

    @classmethod
    def generate(cls) -> Key:
        """Create a key from a fresh random seed."""
        raise NotImplementedError

    @classmethod
    def from_seed(cls, seed: bytes) -> Key:
        """Recreate a key from its 32-byte Ed25519 seed."""
        raise NotImplementedError

    @property
    def aid(self) -> str:
        """The non-transferable AID — 44 characters, ``B`` prefixed, also the verifying key."""
        raise NotImplementedError

    @property
    def seed(self) -> bytes:
        """The 32-byte seed, for a caller that has to persist the key somewhere."""
        raise NotImplementedError

    def sign(self, data: bytes) -> bytes:
        """Sign bytes, returning the raw 64-byte Ed25519 signature.

        Raw rather than CESR-qualified, because RFC 9421 carries the signature as an RFC 8941 byte
        sequence and qualifying it here would only mean unqualifying it at the header.
        """
        raise NotImplementedError


def verifying_key(aid: str) -> bytes:
    """Recover the raw 32-byte Ed25519 public key from a non-transferable AID.

    Raises :class:`~fiki.errors.MalformedKey` for anything that is not a 44-character ``B…``
    string over the base64url alphabet. Strict by construction: fiki decodes exactly one CESR code
    and refuses every other, so it can only ever be narrower than a full CESR implementation.
    """
    raise NotImplementedError

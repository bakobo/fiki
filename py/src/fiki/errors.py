"""fiki's exception taxonomy (``this.i`` @8zw78n0v).

A small closed set of classes under one base. A consumer catches :class:`FikiError` to mean "this
request was not usable", or discriminates by type when it cares which obstacle it hit.

fiki depends on no Bakobo error package, deliberately: a dependency that travels into every
language port is a dependency every port has to reimplement, and the point of this library is that
a cron job can install it. heti maps these classes onto its own ``e.input.*`` and ``e.proof.*``
codes at the boundary, with a test walking ``FikiError.__subclasses__()`` that fails if any class
here has no mapping — so adding a class below is a change heti's suite will notice.

The set is as FINE-GRAINED as heti's code taxonomy, which is why there are separate classes for
conditions a coarser library would fold together — a missing ``Signature`` header against an
unparsable one, a label that is absent against one that is duplicated. That taxonomy was built
deliberately (heti @x2r7mv) so a sender can be told which header to fix rather than handed the
pair, and a fiki that collapsed them would silently narrow heti's public error surface the moment
heti delegated here. The granularity is a contract, not a preference.
"""

from __future__ import annotations


class FikiError(Exception):
    """Base for every error fiki raises about a request."""


class _Detailed(FikiError):
    """A base for errors that carry the value they are about, as an attribute.

    A consumer translating fiki's errors into its own vocabulary needs the offending component
    name, label, keyid or algorithm — and reading it back out of the message text would make
    every reworded sentence a breaking change for that consumer. heti does exactly this
    translation (heti @4n9m4xfz), so the values are structured rather than prose.
    """

    _fields: tuple[str, ...] = ()

    def __init__(self, message: str, **fields: str):
        super().__init__(message)
        for name in self._fields:
            setattr(self, name, fields[name])


# --- something the request needs is absent ---

class MissingSignature(FikiError):
    """The request has no ``Signature`` header, so there is nothing to verify."""


class MissingSignatureInput(FikiError):
    """The request has no ``Signature-Input`` header, so no covered components are declared."""


class MissingSignatureLabel(_Detailed):
    """The two signature headers name different labels, so neither describes the other."""

    _fields = ("label",)


class MissingKey(FikiError):
    """The signature carries no keyid and the caller supplied no key."""


class MissingComponent(_Detailed):
    """A covered component has no value in the request, so the base cannot be rebuilt."""

    _fields = ("component",)


# --- something the request carries cannot be read ---

class MalformedSignature(FikiError):
    """The ``Signature`` header could not be parsed as an RFC 8941 dictionary."""


class MalformedSignatureInput(FikiError):
    """The ``Signature-Input`` header could not be parsed as an RFC 8941 dictionary."""


class MalformedSignatureLabel(FikiError):
    """The signature headers carry other than exactly one label."""


class MalformedSignatureValue(FikiError):
    """The ``Signature`` value is not an RFC 8941 byte sequence, so there is no signature."""


class MalformedKey(_Detailed):
    """A key, keyid, or AID is not a well-formed 32-byte Ed25519 public key."""

    _fields = ("keyid",)


class MalformedDigest(FikiError):
    """The ``Content-Digest`` header could not be parsed, or names no algorithm fiki computes."""


# --- fiki understood the request and will not handle it ---

class UnsupportedComponent(_Detailed):
    """The covered set names a derived component fiki does not build."""

    _fields = ("component", "supported")


class UnsupportedAlgorithm(_Detailed):
    """The signature names an algorithm fiki does not verify."""

    _fields = ("alg",)


class UncoveredBody(FikiError):
    """The request carries a body and the covered set does not include ``content-digest``.

    Raised at signing time rather than warned about, because a verifier has no way to discover
    after the fact that a body was never covered (@2hwvpm42).
    """


# --- the request was read, and it does not hold up ---

class DigestMismatch(FikiError):
    """The received body does not hash to the covered ``Content-Digest``."""


class SignatureMismatch(FikiError):
    """The signature does not verify over the request under the signer's key."""

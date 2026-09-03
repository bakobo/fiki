"""fiki's exception taxonomy (``this.i`` @8zw78n0v).

A small closed set of classes under one base. A consumer catches :class:`FikiError` to mean "this
request was not usable", or discriminates by type when it cares which obstacle it hit.

fiki depends on no Bakobo error package, deliberately: a dependency that travels into every
language port is a dependency every port has to reimplement, and the point of this library is that
a cron job can install it. heti maps these classes onto its own ``e.input.*`` and ``e.proof.*``
codes at the boundary, with a test walking ``FikiError.__subclasses__()`` that fails if any class
here has no mapping — so adding a class below is a change heti's suite will notice.
"""

from __future__ import annotations


class FikiError(Exception):
    """Base for every error fiki raises about a request."""


class UnsupportedComponent(FikiError):
    """The covered set names a derived component fiki does not build."""


class MissingComponent(FikiError):
    """A covered component has no value in the request, so the base cannot be rebuilt."""


class UncoveredBody(FikiError):
    """The request carries a body and the covered set does not include ``content-digest``.

    Raised at signing time rather than warned about, because a verifier has no way to discover
    after the fact that a body was never covered (@2hwvpm42).
    """


class MalformedKey(FikiError):
    """A key or AID is not a well-formed 32-byte Ed25519 public key."""


class MalformedSignature(FikiError):
    """The ``Signature`` or ``Signature-Input`` header could not be parsed."""


class DigestMismatch(FikiError):
    """The received body does not hash to the covered ``Content-Digest``."""


class SignatureMismatch(FikiError):
    """The signature does not verify over the request under the signer's key."""

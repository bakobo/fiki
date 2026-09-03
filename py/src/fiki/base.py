"""The RFC 9421 signature base (section 2.5).

Public surface, not an internal detail. When two implementations disagree about a signature, the
base is where they disagree, and a caller debugging an interop failure needs to see the bytes both
sides actually hashed. That is not hypothetical: keripy's KERI-flavored base diverges from RFC 9421
in three ways while emitting a conformant ``Signature-Input`` header, so a standards-conformant
verifier parses the header, computes a different base, and reports a bad signature.

Derived components fiki builds: ``@method``, ``@authority``, ``@path``, ``@query``. Anything else
raises rather than being skipped — a component silently dropped from the base is a component the
caller believes is covered and is not.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

DERIVED = ("@method", "@authority", "@path", "@query")

# @method, @authority, @path, @query, and created — plus content-digest whenever there is a body
# (@2hwvpm42). This closes the query, host, and body gaps that heti's KERI dialect leaves open and
# structurally cannot close.
DEFAULT_COVERED = ("@method", "@authority", "@path", "@query")


def signature_base(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    covered: Sequence[str],
    created: int,
    keyid: str,
    alg: str | None = None,
    expires: int | None = None,
    nonce: str | None = None,
    tag: str | None = None,
) -> bytes:
    """Build the RFC 9421 signature base for a request.

    ``url`` is a full URL rather than heti's ``path``, because ``@authority`` and ``@query`` cannot
    be derived from a path alone — and those two are exactly what fiki covers and heti cannot.

    Raises :class:`~fiki.errors.UnsupportedComponent` for a derived component outside
    :data:`DERIVED`, and :class:`~fiki.errors.MissingComponent` for a covered header the request
    does not carry.
    """
    raise NotImplementedError

"""The RFC 9421 signature base (section 2.5).

Public surface, not an internal detail. When two implementations disagree about a signature, the
base is where they disagree, and a caller debugging an interop failure needs to see the bytes both
sides actually hashed. That is not hypothetical: keripy's KERI-flavored base diverges from RFC 9421
in three ways while emitting a conformant ``Signature-Input`` header, so a standards-conformant
verifier parses the header, computes a different base, and reports a bad signature.

Derived components fiki builds: ``@method``, ``@authority``, ``@path``, ``@query``. Anything else
raises rather than being skipped — a component silently dropped from the base is a component the
caller believes is covered and is not, which is exactly the shape of the gap in heti's KERI
dialect (@2hwvpm42).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

import http_sfv

from .errors import MissingComponent, UnsupportedComponent

DERIVED = ("@method", "@authority", "@path", "@query")

# @method, @authority, @path, @query — plus content-digest whenever there is a body (@2hwvpm42).
# This closes the query, host, and body gaps that heti's KERI dialect leaves open and structurally
# cannot close. `created` is a signature parameter rather than a component, so it is not listed
# here even though it is always covered.
DEFAULT_COVERED = ("@method", "@authority", "@path", "@query")  # ~2ut3 — nothing consumes it yet

CONTENT_DIGEST = "content-digest"

# RFC 9421 section 2.3. Order is the signer's choice — a verifier reserializes whatever it
# received — so fiki fixes one order and keeps it, which makes its own output reproducible.
_PARAM_ORDER = ("created", "expires", "nonce", "alg", "keyid", "tag")

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def _authority(parts) -> str:
    """The authority, normalized per RFC 9421 section 2.2.3: lowercase host, default port omitted."""
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is None or port == _DEFAULT_PORTS.get(parts.scheme.lower()):
        return host
    return f"{host}:{port}"


def _component_value(component: str, method: str, parts, headers: Mapping[str, str]) -> str:
    if component == "@method":
        return method.upper()
    if component == "@authority":
        return _authority(parts)
    if component == "@path":
        # An empty path is the "/" the origin server would have received.
        return parts.path or "/"
    if component == "@query":
        # Section 2.2.7: the whole query string including the leading "?", percent-encoding
        # preserved, and a bare "?" when the request carries no query at all.
        return f"?{parts.query}"
    if component.startswith("@"):
        raise UnsupportedComponent(
            f'fiki does not build the derived component "{component}"; it builds '
            f"{', '.join(DERIVED)}."
        )
    value = headers.get(component)
    if value is None:
        raise MissingComponent(
            f'The signature covers "{component}", but the request carries no value for it, '
            f"so the signature base cannot be built."
        )
    return value


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
    parts = urlsplit(url)
    # Header field names are case-insensitive and appear lowercased in the base (section 2.1);
    # values are stripped of leading and trailing whitespace.
    lowered = {name.lower(): value.strip() for name, value in headers.items()}
    covered = [component.lower() for component in covered]

    lines = [
        f'"{component}": {_component_value(component, method, parts, lowered)}'
        for component in covered
    ]

    params = http_sfv.InnerList([http_sfv.Item(component) for component in covered])
    values = {
        "created": created,
        "expires": expires,
        "nonce": nonce,
        "alg": alg,
        "keyid": keyid,
        "tag": tag,
    }
    for name in _PARAM_ORDER:
        if values[name] is not None:
            params.params[name] = values[name]
    lines.append(f'"@signature-params": {params}')

    return "\n".join(lines).encode("utf-8")

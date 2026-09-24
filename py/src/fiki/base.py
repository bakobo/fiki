"""The RFC 9421 signature base (section 2.5).

Public surface, not an internal detail. When two implementations disagree about a signature, the
base is where they disagree, and a caller debugging an interop failure needs to see the bytes both
sides actually hashed. That is not hypothetical: keripy's KERI-flavored base diverges from RFC 9421
in three ways while emitting a conformant ``Signature-Input`` header, so a standards-conformant
verifier parses the header, computes a different base, and reports a bad signature.

Derived components fiki builds: ``@method``, ``@authority``, ``@path``, ``@query`` in a request,
and ``@status`` in a response, which may also name its request's components with the ``req``
parameter of section 2.4 (@7f28p7xk). Anything else raises rather than being skipped — a
component silently dropped from the base is a component the caller believes is covered and is
not, which is exactly the shape of the gap in heti's KERI dialect (@2hwvpm42).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import http_sfv

from .errors import DuplicateComponent, MissingComponent, SignatureMismatch, UnsupportedComponent

DERIVED = ("@method", "@authority", "@path", "@query")

# The one derived component a response has of its own (RFC 9421 section 2.2.9). Every request
# component reaches a response only through `req`.
RESPONSE_DERIVED = ("@status",)

# @method, @authority, @path, @query — plus content-digest whenever there is a body (@2hwvpm42).
# This closes the query, host, and body gaps that heti's KERI dialect leaves open and structurally
# cannot close. `created` is a signature parameter rather than a component, so it is not listed
# here even though it is always covered.
DEFAULT_COVERED = ("@method", "@authority", "@path", "@query")

CONTENT_DIGEST = "content-digest"

# The only component parameter fiki supports, and only in a response (RFC 9421 section 2.4).
_REQ = "req"

# RFC 9421 section 2.3. Order is the signer's choice — a verifier reserializes whatever it
# received — so fiki fixes one order and keeps it, which makes its own output reproducible.
_PARAM_ORDER = ("created", "expires", "nonce", "alg", "keyid", "tag")

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


@dataclass(frozen=True)
class Request:
    """The request a response answers, which a response's ``req`` components are read from."""

    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = None


def component(spec: str | http_sfv.Item) -> http_sfv.Item:
    """A component identifier from a caller's spelling of it.

    A plain name (``"@method"``, ``"Content-Digest"``) or its RFC 8941 serialization with
    parameters (``'"@method";req'``). Names are lowercased as a convenience to a local caller; a
    name parsed from the wire is never lowercased, and is refused instead when it is not already.
    """
    if isinstance(spec, http_sfv.Item):
        return spec
    if spec.startswith('"'):
        item = http_sfv.Item()
        try:
            item.parse(spec.encode("utf-8"))
        except ValueError as ex:
            raise UnsupportedComponent(
                f"fiki cannot read {spec} as a component identifier; name a component plainly, "
                'as "@path", or in its serialized form, as \'"@path";req\'.',
                component=spec,
                supported=", ".join(DERIVED + RESPONSE_DERIVED),
            ) from ex
        item.value = item.value.lower()
        return item
    return http_sfv.Item(spec.lower())


def req(name: str) -> str:
    """The spelling of a request component named from a response: ``req("@path")``."""
    item = http_sfv.Item(name.lower())
    item.params[_REQ] = True
    return str(item)


def spec_of(item: http_sfv.Item) -> str:
    """The inverse of :func:`component`: a plain name when it has no parameters."""
    return str(item) if item.params else item.value


def identity(item: http_sfv.Item) -> tuple:
    """What two identifiers must share to be the same component. Parameter order is not it."""
    return (item.value, tuple(sorted(item.params.items())))


def check_covered(items: Sequence[http_sfv.Item], *, response: bool) -> None:
    """Refuse a covered list fiki cannot build faithfully: duplicates first, then the unsupported.

    That order is the KERI profile's section 9, so a list that is both has one correct refusal.
    """
    seen = set()
    for item in items:
        if identity(item) in seen:
            raise DuplicateComponent(
                f"The covered components name {spec_of(item)} twice, so the signature base would "
                "not be what either copy says it is.",
                component=spec_of(item),
            )
        seen.add(identity(item))

    for item in items:
        params = dict(item.params)
        is_req = params.get(_REQ) is True
        if set(params) - {_REQ} or (_REQ in params and not (is_req and response)):
            raise UnsupportedComponent(
                f"fiki does not support the component {spec_of(item)}: the only component "
                f'parameter it supports is "{_REQ}", and only in a response.',
                component=spec_of(item),
                supported=_REQ,
            )
        if item.value.startswith("@"):
            supported = DERIVED if (is_req or not response) else RESPONSE_DERIVED
            if item.value not in supported:
                raise UnsupportedComponent(
                    f'fiki does not build the derived component {spec_of(item)} in a '
                    f"{'response' if response else 'request'}; it builds {', '.join(supported)}.",
                    component=spec_of(item),
                    supported=", ".join(supported),
                )


@dataclass(frozen=True)
class _Message:
    headers: Mapping[str, str]
    method: str | None = None
    parts: object = None
    status: int | None = None
    request: _Message | None = None


def _lowered(headers: Mapping[str, str]) -> dict[str, str]:
    # Header field names are case-insensitive and appear lowercased in the base (section 2.1);
    # values are stripped of leading and trailing whitespace.
    return {name.lower(): value.strip() for name, value in headers.items()}


def request_message(method: str, url: str, headers: Mapping[str, str]) -> _Message:
    return _Message(headers=_lowered(headers), method=method, parts=urlsplit(url))


def response_message(status: int, headers: Mapping[str, str], request: Request | None) -> _Message:
    return _Message(
        headers=_lowered(headers),
        status=status,
        request=None if request is None else request_message(
            request.method, request.url, request.headers
        ),
    )


def _authority(parts, headers: Mapping[str, str]) -> str:
    """The authority, normalized per RFC 9421 section 2.2.3: lowercase host, default port omitted.

    A relative URL falls back to the ``Host`` header, which in HTTP/1.1 *is* the authority. That
    is the shape a server-side verifier actually has — a request target and a header block, never
    a reconstructed absolute URL — and synthesizing a URL to get one would mean guessing a scheme,
    which is precisely the input the default-port rule turns on. Nothing is normalized away in
    that case, because without a scheme no port is a default port.
    """
    if parts.netloc:
        host = (parts.hostname or "").lower()
        port = parts.port
        if port is None or port == _DEFAULT_PORTS.get(parts.scheme.lower()):
            return host
        return f"{host}:{port}"
    host = headers.get("host")
    if host is None:
        raise MissingComponent(
            'The signature covers "@authority", but the URL carries no authority and the '
            "request has no Host header, so there is nothing to derive it from.",
            component="@authority",
        )
    return host.lower()


def _component_value(item: http_sfv.Item, message: _Message) -> str:
    name = item.value
    if item.params.get(_REQ) is True:
        if message.request is None:
            raise MissingComponent(
                f"The signature covers {spec_of(item)}, which is read from the request this "
                "response answers, and no request was supplied.",
                component=spec_of(item),
            )
        message = message.request
    if name == "@status":
        # Section 2.2.9: the three-digit status code. Anything else is not a status this
        # component can carry, so there is no value to sign or to check.
        status = message.status
        if type(status) is not int or not 100 <= status <= 999:
            raise MissingComponent(
                f"The signature covers @status, and {status!r} is not a three-digit HTTP status "
                "code, so there is no status line to build.",
                component="@status",
            )
        return str(status)
    if name == "@method":
        # Section 2.2.1: the method as sent, with no case transformation (@22g0xkr8).
        return message.method
    if name == "@authority":
        return _authority(message.parts, message.headers)
    if name == "@path":
        # An empty path is the "/" the origin server would have received.
        return message.parts.path or "/"
    if name == "@query":
        # Section 2.2.7: the whole query string including the leading "?", percent-encoding
        # preserved, and a bare "?" when the request carries no query at all.
        return f"?{message.parts.query}"
    value = message.headers.get(name)
    if value is None:
        raise MissingComponent(
            f"The signature covers {spec_of(item)}, but the message carries no value for it, "
            f"so the signature base cannot be built.",
            component=spec_of(item),
        )
    return value


def value_of(item: http_sfv.Item, message: _Message) -> str:
    """A component's value, refused when it has no single serialization both sides agree on.

    A line break inside a value would forge a line of the base, and a byte outside visible ASCII
    is encoded differently by different stacks. The KERI profile's draft 6 names such a base
    unbuildable, and so a signature-mismatch (@2f227n4r).
    """
    value = _component_value(item, message)
    if any(not (char == "\t" or " " <= char <= "~") for char in value):
        raise SignatureMismatch(
            f"The value of {spec_of(item)} contains a line break, a control character or a "
            "non-ASCII character, so there is no signature base both sides would build from it."
        )
    return value


def lines_for(items: Sequence[http_sfv.Item], message: _Message) -> list[str]:
    """Every line of the signature base except the trailing ``@signature-params``."""
    return [f"{item}: {value_of(item, message)}" for item in items]


def component_lines(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    covered: Sequence[str],
) -> list[str]:
    """Every line of a request's signature base except the trailing ``@signature-params``.

    Split out because the verify side cannot call :func:`signature_base`: it must reserialize the
    parameters exactly as they arrived, in the order they arrived, rather than in fiki's own fixed
    order — a verifier that reorders what it received computes a different base and rejects a good
    signature.
    """
    items = [component(spec) for spec in covered]
    check_covered(items, response=False)
    return lines_for(items, request_message(method, url, headers))


def _finish(lines: list[str], items, **values) -> bytes:
    params = http_sfv.InnerList(list(items))
    for name in _PARAM_ORDER:
        if values[name] is not None:
            params.params[name] = values[name]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines).encode("utf-8")


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

    Raises :class:`~fiki.errors.DuplicateComponent` for a component named twice,
    :class:`~fiki.errors.UnsupportedComponent` for a derived component outside :data:`DERIVED` or
    a component parameter, and :class:`~fiki.errors.MissingComponent` for a covered header the
    request does not carry.
    """
    items = [component(spec) for spec in covered]
    check_covered(items, response=False)
    lines = lines_for(items, request_message(method, url, headers))
    return _finish(lines, items, created=created, expires=expires, nonce=nonce, alg=alg,
                   keyid=keyid, tag=tag)


def response_signature_base(
    *,
    status: int,
    headers: Mapping[str, str],
    covered: Sequence[str],
    created: int,
    keyid: str,
    request: Request | None = None,
    alg: str | None = None,
    expires: int | None = None,
    nonce: str | None = None,
    tag: str | None = None,
) -> bytes:
    """Build the RFC 9421 signature base for a response (sections 2.2.9 and 2.4).

    ``request`` is the request being answered, which ``req`` components are read from — spelled
    ``req("@path")`` or ``'"@path";req'``. Without one, a ``req`` component is a
    :class:`~fiki.errors.MissingComponent`.
    """
    items = [component(spec) for spec in covered]
    check_covered(items, response=True)
    lines = lines_for(items, response_message(status, headers, request))
    return _finish(lines, items, created=created, expires=expires, nonce=nonce, alg=alg,
                   keyid=keyid, tag=tag)

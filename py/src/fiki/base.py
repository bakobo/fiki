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

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit

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

# RFC 9110 section 5.6.2: a token is one or more tchar. A method is one (section 9.1), and so is a
# field name (section 5.1), which fiki further requires lowercased in a covered list.
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
# RFC 8941 section 3.3.3: an sf-string holds printable ASCII and nothing else.
_SF_STRING = re.compile(r"[\x20-\x7e]*")
# RFC 8941 section 3.1.2: a dictionary key, which is what a signature label is.
_SF_KEY = re.compile(r"[a-z*][a-z0-9_.*-]*")
# RFC 8941 section 3.3.1: at most fifteen digits.
_SF_INTEGER_MAX = 999_999_999_999_999
_PORT_MAX = 65535
# RFC 3986 section 3.2.2's IPvFuture, spelled as urlsplit checks it from Python 3.11.4.
_IPVFUTURE = re.compile(r"v[0-9A-Fa-f]+\..+")


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
    A field name that is not a token is the caller's mistake, a ValueError, because it would be
    serialized into Signature-Input as given (@5zrf8gjk); a derived name fiki does not build is
    refused later, as UnsupportedComponent, which names it.
    """
    if isinstance(spec, http_sfv.Item):
        return spec
    item = _component_item(spec)
    if not item.value.startswith("@") and not _TOKEN.fullmatch(item.value):
        raise ValueError(
            f"{spec!r} is not a component fiki can name: a field is named by an HTTP field name, "
            "one or more token characters, and a derived component by its @ name."
        )
    return item


def _component_item(spec: str) -> http_sfv.Item:
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
    url: str | None = None
    status: int | None = None
    request: _Message | None = None
    # A message handed to a verifier rather than built by a signer, which decides what a URL that
    # cannot be read is: a base that cannot be built when it arrived, a caller error when signing.
    received: bool = False


# RFC 9110 section 5.5: the optional whitespace around a field value is SP and HTAB, and nothing
# else. str.strip() would also remove CR, LF, VT, FF and Unicode spaces, so a value with a line
# break at its edge would build the same line as one without (tick 4r5h).
_OWS = " \t"


def canonical(headers: Mapping[str, str]) -> dict[str, str]:
    """The headers with lowercased names, refusing two names equal case-insensitively.

    Field names are case-insensitive and appear lowercased in the base (section 2.1), so
    ``X-Role`` beside ``x-role`` is one field given two values. Collapsing them would let one
    value be signed or digested and the other reach the application, so it is a ValueError, a
    mistake in the call (@235933km). Values are kept as received: value_of checks them raw and
    only then trims _OWS. Idempotent, so a mapping canonicalized once reads the same everywhere.
    """
    out: dict[str, str] = {}
    for name, value in headers.items():
        if type(name) is not str or type(value) is not str:
            raise TypeError(
                f"A header is a name and a value, both strings; this one is {name!r}: {value!r}."
            )
        lowered = name.lower()
        if lowered in out:
            raise ValueError(
                f'The headers name the field "{lowered}" more than once, in different cases, '
                "and a field has one value; combine them before calling fiki."
            )
        out[lowered] = value
    return out


_lowered = canonical


def check_method(method) -> None:
    """A request's method is an RFC 9110 token, covered or not, or the call is a mistake.

    Its case is kept as given (@22g0xkr8). Checked wherever a request message is built, on sign
    and verify alike (@5zrf8gjk): an empty or spaced method is never a request anybody sent.
    """
    if not isinstance(method, str):
        raise TypeError(f"A request's method is a string; this one is {method!r}.")
    if not _TOKEN.fullmatch(method):
        raise ValueError(
            f"The method {method!r} is not an HTTP method: a method is one or more token "
            "characters, with no spaces, line breaks or separators."
        )


def request_message(method: str, url: str, headers: Mapping[str, str], *,
                    received: bool = False) -> _Message:
    check_method(method)
    return _Message(headers=_lowered(headers), method=method, url=url, received=received)


def response_message(status: int, headers: Mapping[str, str], request: Request | None, *,
                     received: bool = False) -> _Message:
    return _Message(
        headers=_lowered(headers),
        status=status,
        request=None if request is None else request_message(
            request.method, request.url, request.headers, received=received
        ),
        received=received,
    )


def _unreadable(message: _Message, reason: str) -> Exception:
    """A URL fiki cannot read: the caller's mistake when signing, an unbuildable base when not.

    The profile's section 9 names a base that cannot be built a signature-mismatch, so a received
    URL with a port that is not one is refused like any other base that does not verify, never
    raised as an exception from outside fiki's taxonomy (@5zrf8gjk).
    """
    if message.received:
        return SignatureMismatch(
            f"The URL {message.url!r} cannot be read: {reason} So there is no signature base to "
            "check the signature against."
        )
    return ValueError(f"The URL {message.url!r} cannot be read: {reason}")


# A scheme, "://", and at least one character of authority (RFC 3986 section 3).
_ABSOLUTE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/?#]")


def _split(message: _Message):
    """The target as RFC 9112 section 3.2 reads it (@524c8qgv).

    A target beginning with "/" is origin-form: everything before the first "?" is the path,
    verbatim, however many slashes it starts with, and it has no authority of its own, so
    _authority reads the Host header. urlsplit would read "//evil.example/p" as a network-path
    reference and let the sender choose the authority (review A1). Anything else must be an
    absolute URI with a non-empty authority. A space or an ASCII control anywhere is refused
    rather than stripped, as urlsplit strips a tab, CR or LF, which made "/\nx" verify as "/x".
    """
    url = message.url
    if any(c <= " " or c == "\x7f" for c in url):
        raise _unreadable(message, "it contains a space or a control character.")
    if url.startswith("/"):
        target = url.partition("#")[0]
        path, _, query = target.partition("?")
        return SplitResult("", "", path, query, "")
    if not _ABSOLUTE.match(url):
        raise _unreadable(message, "it is neither origin-form, beginning with a slash, nor an "
                                   "absolute URI with a scheme and an authority.")
    try:
        return urlsplit(url)
    except ValueError as ex:
        raise _unreadable(message, f"{ex}.") from ex


def _port(text: str, message: _Message) -> int | None:
    """RFC 3986 section 3.2.3: any run of ASCII digits, read as a number (@5zrf8gjk).

    So :000080 is port 80 and the default port of http. An empty port is no port at all, as
    section 6.2.3 normalizes it.
    """
    if not text:
        return None
    # Leading zeros go first, so no digit string longer than five is ever converted: Python
    # refuses one of over 4300 digits with a ValueError outside fiki's taxonomy.
    digits = text.lstrip("0")
    if (not text.isascii() or not text.isdigit() or len(digits) > 5
            or int(digits or "0") > _PORT_MAX):
        raise _unreadable(message, f"its port {text!r} is not a number from 0 to {_PORT_MAX}.")
    return int(digits or "0")


def ip_literal(text: str) -> bool:
    """RFC 3986 section 3.2.2: an IPv6 address, with an optional zone, or IPvFuture (@9g24rdns).

    What may sit between an IP-literal's brackets. urlsplit checks this itself only from Python
    3.11.4, so fiki checks it on every Python it supports, with the grammar urlsplit uses.
    """
    if text.startswith("v"):
        return _IPVFUTURE.fullmatch(text) is not None
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _authority(message: _Message) -> str:
    """The authority, normalized per RFC 9421 section 2.2.3: lowercase host, default port omitted.

    A relative URL falls back to the ``Host`` header, which in HTTP/1.1 *is* the authority. That
    is the shape a server-side verifier actually has — a request target and a header block, never
    a reconstructed absolute URL — and synthesizing a URL to get one would mean guessing a scheme,
    which is precisely the input the default-port rule turns on. Nothing is normalized away in
    that case, because without a scheme no port is a default port.

    The host and port are read from the authority as written rather than through urlsplit's
    ``hostname`` and ``port``, whose leniencies differ across Python releases (@9g24rdns). An
    IP-literal keeps its brackets, as RFC 3986 section 3.2.2 makes them part of the host, and
    nothing but a port may follow its closing bracket.
    """
    parts = _split(message)
    headers = message.headers
    if parts.netloc:
        hostport = parts.netloc.rpartition("@")[2]
        # From Python 3.11.4 urlsplit refuses all of this itself, as "Invalid IPv6 URL" and the
        # like, which _split made unreadable; before it, only an unbalanced bracket. fiki checks
        # every Python it supports alike, so the IP-literal rule does not turn on a patch release.
        if hostport.startswith("["):
            host, closed, rest = hostport.partition("]")
            if not closed or not ip_literal(host[1:]) or rest[:1] not in ("", ":"):
                raise _unreadable(message, "its IP-literal is not an IPv6 address or IPvFuture "
                                           "in brackets followed by nothing but a port.")
            host, port_text = host + "]", rest[1:]
        else:
            host, _, port_text = hostport.partition(":")
            if "[" in host or "]" in host:
                raise _unreadable(message, "a bracket belongs only around an IP-literal.")
        port = _port(port_text, message)
        host = host.lower()
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
    _check_raw(host, "@authority")
    return host.strip(_OWS).lower()


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
        # Section 2.2.1: the method as sent, with no case transformation (@22g0xkr8). A request
        # has a method, so an absent or empty one is a caller who lost it, never an empty line.
        # request_message checked it is a token (@5zrf8gjk).
        return message.method
    if name == "@authority":
        return _authority(message)
    if name == "@path":
        # An empty path is the "/" the origin server would have received.
        return _split(message).path or "/"
    if name == "@query":
        # Section 2.2.7: the whole query string including the leading "?", percent-encoding
        # preserved, and a bare "?" when the request carries no query at all.
        return f"?{_split(message).query}"
    value = message.headers.get(name)
    if value is None:
        raise MissingComponent(
            f"The signature covers {spec_of(item)}, but the message carries no value for it, "
            f"so the signature base cannot be built.",
            component=spec_of(item),
        )
    # Checked as received, before the optional whitespace is trimmed, so a line break at the
    # edge of a value is refused exactly as one inside it is (tick 4r5h).
    _check_raw(value, spec_of(item))
    return value.strip(_OWS)


def _check_raw(value: str, spec: str) -> None:
    """Refuse a value with no single serialization both sides agree on.

    A line break inside a value would forge a line of the base, and a byte outside visible ASCII
    is encoded differently by different stacks. The KERI profile's draft 6 names such a base
    unbuildable, and so a signature-mismatch (@2f227n4r).
    """
    if any(not (char == "\t" or " " <= char <= "~") for char in value):
        raise SignatureMismatch(
            f"The value of {spec} contains a line break, a control character or a "
            "non-ASCII character, so there is no signature base both sides would build from it."
        )


def value_of(item: http_sfv.Item, message: _Message) -> str:
    """A component's value, refused when it has no single serialization both sides agree on."""
    value = _component_value(item, message)
    _check_raw(value, spec_of(item))
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


def check_signer_params(*, created, expires, keyid, alg, nonce, tag) -> None:
    """What a signer serializes must be serializable, or the call is a mistake (@5zrf8gjk).

    created and expires are RFC 8941 integers that are not negative; keyid, alg, nonce and tag
    are sf-strings, printable ASCII only. Checked here rather than left to http_sfv, so a line
    break is refused by name and a bool is never serialized as a bare RFC 8941 boolean.
    """
    for name, value in (("created", created), ("expires", expires)):
        if value is None and name == "expires":
            continue
        if type(value) is not int:
            raise TypeError(f"{name} is a whole number of seconds; this one is {value!r}.")
        if not 0 <= value <= _SF_INTEGER_MAX:
            raise ValueError(
                f"{name} is {value}, and RFC 8941 carries an integer of at most fifteen digits; "
                "fiki signs one from 0 to 999999999999999."
            )
    for name, value in (("keyid", keyid), ("alg", alg), ("nonce", nonce), ("tag", tag)):
        if value is None:
            continue
        if not isinstance(value, str):
            raise TypeError(f"{name} is a string; this one is {value!r}.")
        if not _SF_STRING.fullmatch(value):
            raise ValueError(
                f"The {name} {value!r} holds a character outside printable ASCII, which an "
                "RFC 8941 string cannot carry; a line break there would forge a header line."
            )


def check_label(label) -> None:
    """A signature label is an RFC 8941 dictionary key, or the call is a mistake (@5zrf8gjk)."""
    if not isinstance(label, str):
        raise TypeError(f"A signature label is a string; this one is {label!r}.")
    if not _SF_KEY.fullmatch(label):
        raise ValueError(
            f"The label {label!r} is not an RFC 8941 key: it starts with a lowercase letter or "
            "'*' and continues with lowercase letters, digits, '_', '-', '.' and '*'."
        )


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
    check_signer_params(created=created, expires=expires, keyid=keyid, alg=alg, nonce=nonce,
                        tag=tag)
    message = request_message(method, url, headers)
    items = [component(spec) for spec in covered]
    check_covered(items, response=False)
    lines = lines_for(items, message)
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
    check_signer_params(created=created, expires=expires, keyid=keyid, alg=alg, nonce=nonce,
                        tag=tag)
    message = response_message(status, headers, request)
    items = [component(spec) for spec in covered]
    check_covered(items, response=True)
    lines = lines_for(items, message)
    return _finish(lines, items, created=created, expires=expires, nonce=nonce, alg=alg,
                   keyid=keyid, tag=tag)

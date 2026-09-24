"""Signing and verifying whole HTTP requests and responses (``this.i`` @2hwvpm42, @7xrx5evg).

This is the surface almost every caller wants. It differs from :func:`~fiki.base.signature_base`
in two ways that are guarantees rather than conveniences.

The ``keyid`` is the signer's raw key unless the caller names another (@7xrx5evg, @6g9zjsv9), so
"the request carries its own verifying key" holds for every fiki-signed request whose caller did
not deliberately choose otherwise — and a verifier handed a resolver never falls back to reading
a key out of the keyid. And a body is always covered or the signature is refused (@2hwvpm42):
signing computes a ``Content-Digest`` and puts it in the covered set, verifying recomputes it over
the body it was handed, and a caller who deliberately excludes it while supplying a body gets an
exception instead of a signature.

The bound worth stating plainly: fiki cannot cover a body it was never given. The guarantee is
"hand fiki the body and it is covered, or fiki refuses" — a caller who omits ``body`` gets a valid
signature over a request whose body nothing protects, and no library can detect that from the
inside.
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass

import http_sfv
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .base import (
    CONTENT_DIGEST,
    DEFAULT_COVERED,
    Request,
    check_covered,
    component,
    identity,
    lines_for,
    req,
    request_message,
    response_message,
    response_signature_base,
    signature_base,
    spec_of,
    value_of,
)
from .errors import (
    DigestMismatch,
    InsufficientCoverage,
    MalformedDigest,
    MalformedKey,
    MalformedSignature,
    MalformedSignatureInput,
    MalformedSignatureLabel,
    MalformedSignatureValue,
    MissingKey,
    MissingSignature,
    MissingSignatureInput,
    MissingSignatureLabel,
    SignatureExpired,
    SignatureMismatch,
    SignatureTooOld,
    Unauthenticated,
    UncoveredBody,
    UnknownKey,
    UnsupportedAlgorithm,
)
from .keys import to_aid, verifying_key

ALG = "ed25519"

# RFC 9530. sha-256 on the way out; both are accepted on the way in, because fiki is not the only
# thing that will ever have signed a request it is asked to verify. Every one of these a header
# carries must match; any other algorithm is ignored (RFC 9530 section 2).
_DIGEST_ALGORITHMS = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}
_DIGEST_OUT = "sha-256"

# RFC 9421 section 2.3's six signature parameters and the RFC 8941 type each must have. Anything
# else is refused rather than carried: a parameter fiki does not understand could be one whose
# meaning the signer relied on (@7f28p7xk).
_SIGNATURE_PARAMS = {"created": int, "expires": int, "nonce": str, "alg": str, "keyid": str,
                     "tag": str}
_SIGNATURE_LENGTH = 64
_KEY_LENGTH = 32
# The RFC 8037 "x" form of a raw keyid (@7xrx5evg): 32 bytes, base64url, unpadded.
_RAW_KEYID_LENGTH = 43
_RAW_KEYID = re.compile(rf"[A-Za-z0-9_-]{{{_RAW_KEYID_LENGTH}}}")

# Two hosts disagreeing by a second is ordinary; a verifier that treats it as an attack is
# unusable. Adjustable per call, because a satellite link and a rack are not the same problem.
DEFAULT_SKEW = 5

# The KERI profile's minimum covered sets (section 3), for a verifier's `minimum`. A body adds
# content-digest on top, and a response to a request that had a body adds "content-digest";req.
REQUEST_MINIMUM = ("@method", "@path", "@query")
RESPONSE_MINIMUM = ("@status", req("@method"), req("@path"), req("@query"))

# keyid -> the 32 raw bytes of the Ed25519 key it names, or None when it names no key the caller
# knows. It may raise MalformedKey itself for a keyid that is not a well-formed identifier.
Resolver = Callable[[str], "bytes | None"]


@dataclass(frozen=True)
class Verdict:
    """The outcome of a successful verification. A raise means it did not verify.

    Carries no timestamp and asserts no freshness: the caller supplied the message, and
    ``created`` is whatever the signer put there. Replay is the caller's problem and fiki says so
    rather than implying an endorsement it has not earned.

    ``aid`` is the non-transferable AID of the key that verified — or, when a resolver supplied
    that key, the keyid the resolver vouched for (@6g9zjsv9). ``covered`` names each component as
    :func:`~fiki.base.component` would accept it: a plain name, or its serialized form when it
    carries a parameter, such as ``'"@path";req'``.
    """

    aid: str
    covered: tuple[str, ...]
    keyid: str | None = None


def content_digest(body: bytes) -> str:
    """The RFC 9530 ``Content-Digest`` header value for a body."""
    digest = _DIGEST_ALGORITHMS[_DIGEST_OUT](body).digest()
    return f"{_DIGEST_OUT}=:{base64.b64encode(digest).decode('ascii')}:"


def _covers_body(items) -> bool:
    return any(identity(item) == (CONTENT_DIGEST, ()) for item in items)


def _cover_body(items: list, sending: dict, body: bytes | None, chosen: bool) -> None:
    """Cover a body the caller handed over, or refuse to sign (@2hwvpm42)."""
    if body is None:
        return
    # Whether the caller CHOSE the covered set is the difference between fiki helping and fiki
    # overriding. On the default path a body simply gets covered; on an explicit path, silently
    # adding a component would mean the signature covers something the caller did not ask for,
    # so the same situation is a refusal instead.
    if not _covers_body(items):
        if chosen:
            raise UncoveredBody(
                "This message carries a body, but the covered components do not include "
                f'"{CONTENT_DIGEST}", so the signature would not bind the body. Add it to '
                "the covered set, or omit the body if it is genuinely not part of what you "
                "are signing."
            )
        items.append(component(CONTENT_DIGEST))
    if CONTENT_DIGEST not in {name.lower() for name in sending}:
        sending["Content-Digest"] = content_digest(body)


def _signed(key, base: bytes, label: str, sending: dict, given) -> dict[str, str]:
    signature = key.sign(base)
    params = base.decode("utf-8").rsplit('"@signature-params": ', 1)[1]
    out = {
        "Signature-Input": f"{label}={params}",
        "Signature": f"{label}=:{base64.b64encode(signature).decode('ascii')}:",
    }
    if "Content-Digest" in sending and CONTENT_DIGEST not in {k.lower() for k in (given or {})}:
        out["Content-Digest"] = sending["Content-Digest"]
    return out


def sign_request(
    *,
    key,
    method: str,
    url: str,
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    covered: Sequence[str] | None = None,
    created: int | None = None,
    label: str = "sig",
    expires: int | None = None,
    nonce: str | None = None,
    tag: str | None = None,
    keyid: str | None = None,
    minimum: Sequence[str] | None = None,
) -> dict[str, str]:
    """Sign a request, returning the headers to add to it.

    With a ``body`` and no explicit ``covered``, fiki computes a ``Content-Digest``, returns it
    among the headers, and covers it. With a ``body`` and an explicit ``covered`` that omits
    ``content-digest``, fiki raises :class:`~fiki.errors.UncoveredBody` rather than signing a
    request whose body nothing binds.

    ``method`` is signed exactly as given (@22g0xkr8), so pass it as it will go on the wire.
    ``keyid`` defaults to the key itself (@7xrx5evg); name another, such as a KERI AID, only when
    the verifier resolves it (@6g9zjsv9). ``minimum``, such as :data:`REQUEST_MINIMUM`, makes
    the signer refuse a covered list its verifier would refuse (@2f227n4r).
    """
    sending = dict(headers or {})
    chosen = covered is not None
    items = [component(spec) for spec in (DEFAULT_COVERED if covered is None else covered)]
    _cover_body(items, sending, body, chosen)
    if minimum is not None:
        _check_minimum(items, minimum, has_body=_request_has_body(_lowered(sending), body),
                       request_had_body=False)

    base = signature_base(
        method=method,
        url=url,
        headers=sending,
        covered=items,
        created=int(time.time()) if created is None else created,
        keyid=_keyid(key.aid) if keyid is None else keyid,
        alg=ALG,
        expires=expires,
        nonce=nonce,
        tag=tag,
    )
    return _signed(key, base, label, sending, headers)


def sign_response(
    *,
    key,
    status: int,
    request: Request | None = None,
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    covered: Sequence[str] | None = None,
    created: int | None = None,
    label: str = "sig",
    expires: int | None = None,
    nonce: str | None = None,
    tag: str | None = None,
    keyid: str | None = None,
    minimum: Sequence[str] | None = None,
) -> dict[str, str]:
    """Sign a response, returning the headers to add to it (RFC 9421 section 2.4).

    By default the signature covers ``@status``, a ``Content-Digest`` of any body, and — when the
    ``request`` it answers is given — that request's method, path and query, plus its
    ``content-digest`` when it carried one, each marked ``req``. That binds the response to what
    was asked. The body rule is the same as :func:`sign_request`'s. A request that had a body by
    the verifier's own test is bound by its ``Content-Digest``, and one with no digest to bind is
    refused as :class:`~fiki.errors.UncoveredBody` rather than signed into a response every
    profile client refuses (@2f227n4r).
    """
    sending = dict(headers or {})
    chosen = covered is not None
    had_body = request is not None and _request_has_body(_lowered(request.headers), request.body)
    if covered is None:
        covered = ["@status"]
        if request is not None:
            covered += [req("@method"), req("@path"), req("@query")]
    items = [component(spec) for spec in covered]
    _cover_body(items, sending, body, chosen)
    if not chosen and had_body:
        if CONTENT_DIGEST not in _lowered(request.headers):
            raise UncoveredBody(
                "The request this response answers carried a body and no Content-Digest, so the "
                "response has nothing to bind that body with. Sign the request with a digest "
                "first, or name the covered components yourself."
            )
        items.append(component(req(CONTENT_DIGEST)))
    if minimum is not None:
        _check_minimum(items, minimum, has_body=bool(body), request_had_body=had_body)

    base = response_signature_base(
        status=status,
        headers=sending,
        request=request,
        covered=items,
        created=int(time.time()) if created is None else created,
        keyid=_keyid(key.aid) if keyid is None else keyid,
        alg=ALG,
        expires=expires,
        nonce=nonce,
        tag=tag,
    )
    return _signed(key, base, label, sending, headers)


def verify_request(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    max_age: int | None,
    body: bytes | None = None,
    expected_aid: str | None = None,
    skew: int = DEFAULT_SKEW,
    now: int | None = None,
    resolve: Resolver | None = None,
    minimum: Sequence[str] | None = None,
    expected_keyid: str | None = None,
    authorities: Collection[str] | None = None,
) -> Verdict:
    """Verify a signed request, returning a :class:`Verdict` or raising.

    ``expected_aid`` is authoritative when supplied — the preregistration case, where the verifier
    already knows whose request this should be and the inline key is only a claim. ``resolve`` is
    the other way to be authoritative (@6g9zjsv9): a function from the keyid to the key it names,
    for a keyid such as a transferable AID that does not contain its key. Pass one or neither.

    ``max_age`` has no default and must be given: seconds of tolerance, or ``None`` to decline the
    check. Both defaults would be wrong (@67shl6c5) — a value guesses at somebody else's clock
    skew and replay window, and ``None`` reproduces the silent skip this argument exists to
    remove — so the decision is written at the call site either way. An ``expires`` the signer
    declared is enforced regardless, because ignoring one is selling a guarantee nobody bought.

    ``minimum`` is the verifier's own covered-set policy, such as :data:`REQUEST_MINIMUM`: a
    signature covering less is refused even though it verifies, and so is a body — signalled by
    ``Content-Length`` above zero, any ``Transfer-Encoding``, or simply arriving — without a
    covered ``content-digest`` (@7f28p7xk). ``None`` enforces no minimum, and that includes the
    body rule: with ``minimum=None`` a body handed over with no covered ``content-digest`` is
    accepted, and the verdict's ``covered`` is the only place that shows it (@2f227n4r).

    ``expected_keyid`` refuses a signature by any other keyid as
    :class:`~fiki.errors.UnknownKey`. ``authorities`` is the set of ``@authority`` values this
    verifier serves; a covered ``@authority`` outside it is a
    :class:`~fiki.errors.SignatureMismatch`, because a request signed for one service must not
    replay to another (@2f227n4r).

    ``now`` is injectable so a conformance vector can pin a freshness case against a fixed clock.
    """
    return _verify(
        request_message(method, url, headers), headers, body, response=False, request=None,
        max_age=max_age, expected_aid=expected_aid, skew=skew, now=now, resolve=resolve,
        minimum=minimum, expected_keyid=expected_keyid, authorities=authorities,
    )


def verify_response(
    *,
    status: int,
    headers: Mapping[str, str],
    max_age: int | None,
    request: Request | None = None,
    body: bytes | None = None,
    expected_aid: str | None = None,
    skew: int = DEFAULT_SKEW,
    now: int | None = None,
    resolve: Resolver | None = None,
    minimum: Sequence[str] | None = None,
    expected_keyid: str | None = None,
) -> Verdict:
    """Verify a signed response to ``request``, returning a :class:`Verdict` or raising.

    The arguments are :func:`verify_request`'s, with ``status`` in place of the method and URL and
    the ``request`` the response answers, which its ``req`` components are read from. With
    :data:`RESPONSE_MINIMUM`, a request that had a body also obliges the response to cover
    ``"content-digest";req``. A response's body is its content, never its ``Content-Length``, so
    a HEAD or 304 response is bodiless whatever length it announces. A client should pass
    ``expected_keyid``, the AID it is talking to (profile R1). An unsigned 401 is
    :class:`~fiki.errors.Unauthenticated`, checked before anything else, because a server that
    refuses before it knows the agent cannot sign the refusal (@2f227n4r).
    """
    if status == 401 and not any(name.lower() == "signature" for name in headers):
        raise Unauthenticated(
            "The server answered 401 without signing the answer, so the request was not "
            "authenticated and the body of the refusal cannot be trusted."
        )
    return _verify(
        response_message(status, headers, request), headers, body, response=True,
        request=request, max_age=max_age, expected_aid=expected_aid, skew=skew, now=now,
        resolve=resolve, minimum=minimum, expected_keyid=expected_keyid, authorities=None,
    )


def _verify(message, headers, body, *, response, request, max_age, expected_aid, skew, now,
            resolve, minimum, expected_keyid, authorities) -> Verdict:
    """The KERI profile's section 9 order, so a message has exactly one correct refusal."""
    if expected_aid is not None and resolve is not None:
        raise TypeError("Pass expected_aid or resolve, not both; each decides the key alone.")

    found = {name.lower(): value for name, value in headers.items()}
    inner, signature = _read(found, require_keyid=expected_aid is None)
    items = list(inner)
    check_covered(items, response=response)
    if minimum is not None:
        _check_minimum(
            items, minimum,
            has_body=bool(body) if response else _request_has_body(found, body),
            request_had_body=request is not None and _request_has_body(
                _lowered(request.headers), request.body
            ),
        )

    keyid = inner.params.get("keyid")
    if expected_keyid is not None and keyid != expected_keyid:
        raise UnknownKey(
            f'This message is signed by "{keyid}", and the one expected is "{expected_keyid}".',
            keyid=keyid,
        )
    public_key, aid, keyid = _resolve(expected_aid, keyid, resolve)
    alg = inner.params.get("alg")
    if alg is not None and alg != ALG:
        raise UnsupportedAlgorithm(
            f'This signature is made with "{alg}", and fiki verifies only {ALG} signatures.',
            alg=alg,
        )

    lines = lines_for(items, message)
    lines.append(f'"@signature-params": {inner}')
    base = "\n".join(lines).encode("utf-8")

    try:
        public_key.verify(signature, base)
    except InvalidSignature as ex:
        raise SignatureMismatch(
            "The signature does not match this message under the signer's key, so the message "
            "cannot be treated as authentic."
        ) from ex

    if authorities is not None:
        for item in items:
            if item.value == "@authority" and value_of(item, message) not in authorities:
                raise SignatureMismatch(
                    f'The signature covers the authority "{value_of(item, message)}", which '
                    "this verifier does not serve, so it was signed for somebody else."
                )

    # AFTER the signature check, deliberately. created and expires are covered by the signature,
    # so acting on them before verifying it would mean enforcing a policy against values an
    # attacker could still have chosen — and it would tell that attacker their forgery at least
    # parsed. The clock is read only if one of the two checks is actually live, which is what
    # keeps a message declaring no freshness deterministic (@67shl6c5).
    _check_freshness(inner.params, max_age=max_age, skew=skew, now=now)

    if _covers_body(items):
        _check_digest(found.get(CONTENT_DIGEST), body)

    return Verdict(aid=aid, covered=tuple(spec_of(item) for item in items), keyid=keyid)


def _lowered(headers: Mapping[str, str]) -> dict[str, str]:
    return {name.lower(): value for name, value in headers.items()}


def _request_has_body(found: Mapping[str, str], body: bytes | None) -> bool:
    """The profile's request body test: a length above zero, any transfer coding, or content.

    Requests only. A response's body is its content, since a HEAD or 304 response carries the
    length of a representation it does not send (@2f227n4r).
    """
    if body:
        return True
    if "transfer-encoding" in found:
        return True
    length = found.get("content-length")
    if length is None:
        return False
    # Fail closed: a length that is not a plain decimal, negative ones included, is not evidence
    # that there is no body.
    length = length.strip()
    return not re.fullmatch(r"[0-9]+", length) or int(length) > 0


def _check_minimum(items, minimum, *, has_body: bool, request_had_body: bool) -> None:
    have = {identity(item) for item in items}
    required = [component(spec) for spec in minimum]
    if has_body:
        required.append(component(CONTENT_DIGEST))
    if request_had_body:
        required.append(component(req(CONTENT_DIGEST)))
    for item in required:
        if identity(item) not in have:
            raise InsufficientCoverage(
                f"The signature does not cover {spec_of(item)}, which this verifier requires, so "
                "it is refused even though it may be valid: a signature over too little is a "
                "signature over what an intermediary is free to change.",
                component=spec_of(item),
            )


def _check_freshness(params, *, max_age: int | None, skew: int, now: int | None) -> None:
    """Enforce the verifier's ``max_age``, then the signer's ``expires`` (profile section 9)."""
    expires = params.get("expires")
    if expires is None and max_age is None:
        return
    stamp = int(time.time()) if now is None else now

    if max_age is not None:
        created = params.get("created")
        if created is None:
            raise SignatureTooOld(
                "This signature carries no created timestamp, so its age cannot be checked "
                f"against the {max_age}-second limit you asked for.",
                created=None,
                now=stamp,
                max_age=max_age,
            )
        if stamp - created > max_age + skew:
            raise SignatureTooOld(
                f"This signature was created at {created}, which is more than {max_age} seconds "
                f"before {stamp}, so it is too old to accept.",
                created=created,
                now=stamp,
                max_age=max_age,
            )
        if created - stamp > skew:
            raise SignatureTooOld(
                f"This signature claims to have been created at {created}, which is in the "
                f"future relative to {stamp} by more than the {skew}-second skew allowance.",
                created=created,
                now=stamp,
                max_age=max_age,
            )

    if expires is not None and stamp > expires + skew:
        raise SignatureExpired(
            f"This signature expired at {expires} and it is now {stamp}, so the signer has "
            "already declared it should not be accepted.",
            expires=expires,
            now=stamp,
        )


def _keyid(aid: str) -> str:
    """The raw verifying key, base64url and unpadded — the RFC 8037 JWK "x" form (@7xrx5evg)."""
    raw = verifying_key(aid).public_bytes_raw()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _read(found: Mapping[str, str], *, require_keyid: bool):
    """Pull one signature and its input out of the headers, or say what is wrong with them.

    In the KERI profile's section 9 order: absence before malformation, the Signature header
    before Signature-Input, the members' shape before the label count.
    """
    raw_signature = found.get("signature")
    raw_input = found.get("signature-input")
    if not raw_signature:
        raise MissingSignature(
            "This message has no Signature header, so there is nothing to verify."
        )
    if not raw_input:
        raise MissingSignatureInput(
            "This message has no Signature-Input header, so there is no way to know which "
            "components a signature would cover."
        )

    signatures = _parse(raw_signature, "Signature", MalformedSignature)
    for member in signatures.values():
        # Draft 6 of the KERI profile would call this malformed-signature, since such a header is
        # neither mode's form; the class stays the one the shared vectors pin (@2f227n4r).
        if type(getattr(member, "value", None)) is not bytes:
            raise MalformedSignatureValue(
                "RFC 9421 carries a signature as an RFC 8941 byte sequence, wrapped in colons; "
                "this Signature header carries something else."
            )
    inputs = _parse(raw_input, "Signature-Input", MalformedSignatureInput)
    for member in inputs.values():
        _check_input(member, require_keyid=require_keyid)

    if len(inputs) != 1 or len(signatures) != 1:
        raise MalformedSignatureLabel(
            "fiki verifies a message carrying exactly one signature; this one declares "
            f"{len(inputs)} in Signature-Input and {len(signatures)} in Signature."
        )
    label = next(iter(inputs.keys()))
    if label not in signatures:
        raise MissingSignatureLabel(
            f'The Signature header carries no entry labelled "{label}", so the covered '
            "components describe a signature that is not here.",
            label=label,
        )

    value = signatures[label].value
    if len(value) != _SIGNATURE_LENGTH:
        raise MalformedSignatureValue(
            "RFC 9421 carries an Ed25519 signature as a 64-byte RFC 8941 byte sequence, wrapped "
            "in colons; this one is something else."
        )
    return inputs[label], value


def _check_input(member, *, require_keyid: bool) -> None:
    """Refuse a Signature-Input member fiki would otherwise have to guess about."""
    if not isinstance(member, http_sfv.InnerList):
        raise MalformedSignatureInput(
            "A Signature-Input member is a parenthesized list of covered components; this one "
            "is a single value."
        )
    for item in member:
        if type(item.value) is not str:
            raise MalformedSignatureInput(
                f"Every covered component is named by a quoted string; {item} is not one."
            )
        if not item.value.startswith("@") and item.value != item.value.lower():
            raise MalformedSignatureInput(
                f"The covered field {item} is not lowercase, and RFC 9421 section 2.1 requires "
                "field names in the covered list to be lowercased by the signer."
            )
    if require_keyid and "keyid" not in member.params:
        # Here rather than when the key is resolved: keyid is REQUIRED, so its absence belongs
        # with the other defects of Signature-Input, ahead of the covered list (@2f227n4r).
        raise MissingKey(
            "This signature carries no keyid and no expected_aid was supplied, so there is no "
            "key to verify it against."
        )
    for name, value in member.params.items():
        expected = _SIGNATURE_PARAMS.get(name)
        if expected is None:
            raise MalformedSignatureInput(
                f'The signature parameter "{name}" is not one fiki understands; it accepts '
                f"{', '.join(_SIGNATURE_PARAMS)}."
            )
        if type(value) is not expected:
            raise MalformedSignatureInput(
                f'The signature parameter "{name}" must be '
                f"{'an integer' if expected is int else 'a quoted string'}."
            )


def _parse(raw: str, name: str, error: type[Exception]) -> http_sfv.Dictionary:
    parsed = http_sfv.Dictionary()
    try:
        parsed.parse(raw.encode("utf-8"))
    except Exception as ex:
        raise error(
            f"I could not parse the {name} header; RFC 9421 spells it as an RFC 8941 dictionary."
        ) from ex
    return parsed


def _resolve(expected_aid: str | None, keyid: str | None, resolve: Resolver | None):
    """The key to verify with, the identity to report, and the keyid as received."""
    if expected_aid is not None:
        public_key = verifying_key(expected_aid)
        return public_key, to_aid(public_key.public_bytes_raw()), keyid
    if not keyid:
        raise MissingKey(
            "This signature carries no keyid and no expected_aid was supplied, so there is no "
            "key to verify it against."
        )
    if resolve is not None:
        # The resolver is authoritative: fiki never falls back to decoding the keyid, because a
        # transferable prefix that embeds a key embeds its INCEPTION key (@6g9zjsv9).
        raw = resolve(keyid)
        if raw is None:
            raise UnknownKey(
                f'No key is known for the keyid "{keyid}", so the signature cannot be checked.',
                keyid=keyid,
            )
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != _KEY_LENGTH:
            raise MalformedKey(
                f'The key resolved for "{keyid}" is not a {_KEY_LENGTH}-byte Ed25519 public key.',
                keyid=keyid,
            )
        return Ed25519PublicKey.from_public_bytes(bytes(raw)), keyid, keyid
    # Strictly, as keys.py decodes an AID: a lenient decoder discards characters outside the
    # alphabet and ignores trailing bits, so a keyid that is not the key's encoding could verify
    # as whatever key it happened to decode to. Only the one canonical spelling is a key.
    if not _RAW_KEYID.fullmatch(keyid):
        raise MalformedKey(
            f'The keyid "{keyid}" is not a base64url-encoded 32-byte Ed25519 public key: that is '
            f"exactly {_RAW_KEYID_LENGTH} characters from the base64url alphabet, unpadded.",
            keyid=keyid,
        )
    raw = base64.urlsafe_b64decode(keyid + "=")
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != keyid:
        raise MalformedKey(
            f'The keyid "{keyid}" is not the canonical base64url spelling of any key.',
            keyid=keyid,
        )
    public_key = Ed25519PublicKey.from_public_bytes(raw)
    return public_key, to_aid(public_key.public_bytes_raw()), keyid


def _check_digest(header: str | None, body: bytes | None) -> None:
    """Recompute the digest over the body actually received (@2hwvpm42).

    The header is covered by the signature, so it cannot have been tampered with — but a covered
    digest still only attests to a body nobody hashed until somebody hashes it. Every algorithm
    fiki computes must match; the ones it does not are ignored (RFC 9530 section 2).
    """
    parsed = _parse(header, "Content-Digest", MalformedDigest)
    recognized = []
    for name, member in parsed.items():
        algorithm = _DIGEST_ALGORITHMS.get(name)
        if algorithm is None:
            continue
        expected = getattr(member, "value", None)
        if type(expected) is not bytes:
            raise MalformedDigest(
                f"The {name} Content-Digest is not an RFC 8941 byte sequence, so it cannot be "
                "compared with anything."
            )
        recognized.append((name, algorithm, expected))
    if not recognized:
        raise MalformedDigest(
            "The Content-Digest header names no algorithm fiki computes; it computes "
            f"{' and '.join(sorted(_DIGEST_ALGORITHMS))}."
        )
    if body is None:
        raise DigestMismatch(
            "The signature covers content-digest, but no body was supplied to check it against, "
            "so the body is unverified."
        )
    for name, algorithm, expected in recognized:
        if algorithm(body).digest() != expected:
            raise DigestMismatch(
                f"The body does not match its {name} Content-Digest, so the body is not the one "
                "that was signed."
            )

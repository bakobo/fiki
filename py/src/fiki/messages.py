"""Signing and verifying whole HTTP requests (``this.i`` @2hwvpm42, @7xrx5evg).

This is the surface almost every caller wants. It differs from :func:`~fiki.base.signature_base`
in two ways that are guarantees rather than conveniences.

The ``keyid`` is always the signer's raw key and is not overridable (@7xrx5evg), so "the request
carries its own verifying key" holds for every fiki-signed request rather than being a default
somebody can wander off. And a body is always covered or the signature is refused (@2hwvpm42):
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
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import http_sfv
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .base import CONTENT_DIGEST, DEFAULT_COVERED, component_lines, signature_base
from .errors import (
    DigestMismatch,
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
    UncoveredBody,
    UnsupportedAlgorithm,
)
from .keys import to_aid, verifying_key

ALG = "ed25519"

# RFC 9530. sha-256 on the way out; both are accepted on the way in, because fiki is not the only
# thing that will ever have signed a request it is asked to verify.
_DIGEST_ALGORITHMS = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}
_DIGEST_OUT = "sha-256"

# Two hosts disagreeing by a second is ordinary; a verifier that treats it as an attack is
# unusable. Adjustable per call, because a satellite link and a rack are not the same problem.
DEFAULT_SKEW = 5


@dataclass(frozen=True)
class Verdict:
    """The outcome of a successful verification. A raise means it did not verify.

    Carries no timestamp and asserts no freshness: the caller supplied the request, and ``created``
    is whatever the signer put there. Replay is the caller's problem and fiki says so rather than
    implying an endorsement it has not earned.
    """

    aid: str
    covered: tuple[str, ...]


def content_digest(body: bytes) -> str:
    """The RFC 9530 ``Content-Digest`` header value for a body."""
    digest = _DIGEST_ALGORITHMS[_DIGEST_OUT](body).digest()
    return f"{_DIGEST_OUT}=:{base64.b64encode(digest).decode('ascii')}:"


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
) -> dict[str, str]:
    """Sign a request, returning the headers to add to it.

    With a ``body`` and no explicit ``covered``, fiki computes a ``Content-Digest``, returns it
    among the headers, and covers it. With a ``body`` and an explicit ``covered`` that omits
    ``content-digest``, fiki raises :class:`~fiki.errors.UncoveredBody` rather than signing a
    request whose body nothing binds.
    """
    sending = dict(headers or {})
    # Whether the caller CHOSE the covered set is the difference between fiki helping and fiki
    # overriding. On the default path a body simply gets covered; on an explicit path, silently
    # adding a component would mean the signature covers something the caller did not ask for,
    # so the same situation is a refusal instead (@2hwvpm42).
    chosen = covered is not None
    covered = [component.lower() for component in (DEFAULT_COVERED if covered is None else covered)]

    if body is not None:
        if CONTENT_DIGEST not in covered:
            if chosen:
                raise UncoveredBody(
                    "This request carries a body, but the covered components do not include "
                    f'"{CONTENT_DIGEST}", so the signature would not bind the body. Add it to '
                    "the covered set, or omit the body if it is genuinely not part of what you "
                    "are signing."
                )
            covered.append(CONTENT_DIGEST)
        if CONTENT_DIGEST not in {name.lower() for name in sending}:
            sending["Content-Digest"] = content_digest(body)

    base = signature_base(
        method=method,
        url=url,
        headers=sending,
        covered=covered,
        created=int(time.time()) if created is None else created,
        keyid=_keyid(key.aid),
        alg=ALG,
        expires=expires,
        nonce=nonce,
        tag=tag,
    )
    signature = key.sign(base)

    params = base.decode("utf-8").rsplit('"@signature-params": ', 1)[1]
    out = {
        "Signature-Input": f"{label}={params}",
        "Signature": f"{label}=:{base64.b64encode(signature).decode('ascii')}:",
    }
    if "Content-Digest" in sending and CONTENT_DIGEST not in {k.lower() for k in (headers or {})}:
        out["Content-Digest"] = sending["Content-Digest"]
    return out


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
) -> Verdict:
    """Verify a signed request, returning a :class:`Verdict` or raising.

    ``expected_aid`` is authoritative when supplied — the preregistration case, where the verifier
    already knows whose request this should be and the inline key is only a claim.

    ``max_age`` has no default and must be given: seconds of tolerance, or ``None`` to decline the
    check. Both defaults would be wrong (@67shl6c5) — a value guesses at somebody else's clock
    skew and replay window, and ``None`` reproduces the silent skip this argument exists to
    remove — so the decision is written at the call site either way. An ``expires`` the signer
    declared is enforced regardless, because ignoring one is selling a guarantee nobody bought.

    ``now`` is injectable so a conformance vector can pin a freshness case against a fixed clock.
    """
    found = {name.lower(): value for name, value in headers.items()}
    inner, signature = _read(found)

    alg = inner.params.get("alg")
    if alg is not None and alg != ALG:
        raise UnsupportedAlgorithm(
            f'This signature is made with "{alg}", and fiki verifies only {ALG} signatures.',
            alg=alg,
        )

    covered = tuple(item.value for item in inner)
    public_key = _resolve(expected_aid, inner.params.get("keyid"))

    lines = component_lines(method=method, url=url, headers=headers, covered=covered)
    lines.append(f'"@signature-params": {inner}')
    base = "\n".join(lines).encode("utf-8")

    try:
        public_key.verify(signature, base)
    except InvalidSignature as ex:
        raise SignatureMismatch(
            "The signature does not match this request under the signer's key, so the request "
            "cannot be treated as authentic."
        ) from ex

    # AFTER the signature check, deliberately. created and expires are covered by the signature,
    # so acting on them before verifying it would mean enforcing a policy against values an
    # attacker could still have chosen — and it would tell that attacker their forgery at least
    # parsed. The clock is read only if one of the two checks is actually live, which is what
    # keeps a request declaring no freshness deterministic (@67shl6c5).
    _check_freshness(inner.params, max_age=max_age, skew=skew, now=now)

    if CONTENT_DIGEST in covered:
        _check_digest(found.get(CONTENT_DIGEST), body)

    return Verdict(aid=to_aid(public_key.public_bytes_raw()), covered=covered)


def _check_freshness(params, *, max_age: int | None, skew: int, now: int | None) -> None:
    """Enforce the signer's ``expires`` and the verifier's ``max_age``."""
    expires = params.get("expires")
    if expires is None and max_age is None:
        return
    stamp = int(time.time()) if now is None else now

    if expires is not None and stamp > expires + skew:
        raise SignatureExpired(
            f"This signature expired at {expires} and it is now {stamp}, so the signer has "
            "already declared it should not be accepted.",
            expires=expires,
            now=stamp,
        )
    if max_age is None:
        return

    created = params.get("created")
    if created is None:
        raise SignatureTooOld(
            "This signature carries no created timestamp, so its age cannot be checked against "
            f"the {max_age}-second limit you asked for.",
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
            f"This signature claims to have been created at {created}, which is in the future "
            f"relative to {stamp} by more than the {skew}-second skew allowance.",
            created=created,
            now=stamp,
            max_age=max_age,
        )


def _keyid(aid: str) -> str:
    """The raw verifying key, base64url and unpadded — the RFC 8037 JWK "x" form (@7xrx5evg)."""
    raw = verifying_key(aid).public_bytes_raw()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _read(found: Mapping[str, str]):
    """Pull one signature and its input out of the headers, or say what is wrong with them."""
    raw_input = found.get("signature-input")
    raw_signature = found.get("signature")
    if not raw_input:
        raise MissingSignatureInput(
            "This request has no Signature-Input header, so there is no way to know which "
            "components a signature would cover."
        )
    if not raw_signature:
        raise MissingSignature(
            "This request has no Signature header, so there is nothing to verify."
        )

    inputs = _parse(raw_input, "Signature-Input", MalformedSignatureInput)
    signatures = _parse(raw_signature, "Signature", MalformedSignature)

    labels = list(inputs.keys())
    if len(labels) != 1:
        raise MalformedSignatureLabel(
            f"fiki verifies a request carrying exactly one signature; this one declares "
            f"{len(labels)}."
        )
    if list(signatures.keys()) != labels:
        raise MissingSignatureLabel(
            f'The Signature header carries no entry labelled "{labels[0]}", so the covered '
            "components describe a signature that is not here.",
            label=labels[0],
        )

    value = signatures[labels[0]].value
    if not isinstance(value, (bytes, bytearray)):
        raise MalformedSignatureValue(
            "RFC 9421 carries the signature as an RFC 8941 byte sequence, wrapped in colons; "
            "this one is something else."
        )
    return inputs[labels[0]], bytes(value)


def _parse(raw: str, name: str, error: type[Exception]) -> http_sfv.Dictionary:
    parsed = http_sfv.Dictionary()
    try:
        parsed.parse(raw.encode("utf-8"))
    except Exception as ex:
        raise error(
            f"I could not parse the {name} header; RFC 9421 spells it as an RFC 8941 dictionary."
        ) from ex
    return parsed


def _resolve(expected_aid: str | None, keyid: str | None) -> Ed25519PublicKey:
    if expected_aid is not None:
        return verifying_key(expected_aid)
    if not keyid:
        raise MissingKey(
            "This signature carries no keyid and no expected_aid was supplied, so there is no "
            "key to verify it against."
        )
    try:
        raw = base64.urlsafe_b64decode(keyid + "=" * (-len(keyid) % 4))
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as ex:
        raise MalformedKey(
            f'The keyid "{keyid}" is not a base64url-encoded 32-byte Ed25519 public key.',
            keyid=keyid,
        ) from ex


def _check_digest(header: str | None, body: bytes | None) -> None:
    """Recompute the digest over the body actually received (@2hwvpm42).

    The header is covered by the signature, so it cannot have been tampered with — but a covered
    digest still only attests to a body nobody hashed until somebody hashes it.
    """
    if body is None:
        raise DigestMismatch(
            "The signature covers content-digest, but no body was supplied to check it against, "
            "so the body is unverified."
        )
    parsed = _parse(header, "Content-Digest", MalformedDigest)
    for name, item in parsed.items():
        algorithm = _DIGEST_ALGORITHMS.get(name.lower())
        if algorithm is None:
            continue
        if algorithm(body).digest() != bytes(item.value):
            raise DigestMismatch(
                f"The request body does not match its {name} Content-Digest, so the body is not "
                "the one that was signed."
            )
        return
    raise MalformedDigest(
        "The Content-Digest header names no algorithm fiki computes; it computes "
        f"{' and '.join(sorted(_DIGEST_ALGORITHMS))}."
    )

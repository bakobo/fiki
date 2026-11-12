#!/usr/bin/env python3
"""Regenerate the KERI profile's vector set (``this.i`` @8vwrexxc).

Run from the repository root: ``python3 vectors/keri/generate.py``.

The contract is the KERI profile of RFC 9421 HTTP Message Signatures, version 1.2 of 2026-11-12,
published beside these files at docs/keri-profile.md (``this.i`` @997vxdu7),
which keripy, KERIA and signify-ts implement for WebOfTrust/keripy#1669. fiki generates these
because it shares no code with any of them; the profile's own oracle section asks for exactly
that. This is a separate script from ``vectors/generate.py`` on purpose: the shared vectors are a
contract five ports satisfy, and a KERI-profile change must not be able to rewrite them.

Every byte here comes from running fiki-py, never from a summary of anything, and every case is
checked against fiki before it is written: an accept case must verify, and a refusal case must
raise the error whose profile code the case names. A case whose intended code disagrees with what
fiki does aborts generation rather than being written wrong.

Two things are static data rather than generated. The RFC 9421 B.2.6 case is the RFC's own, and
``legacy.json`` carries the legacy-dialect messages KERIA's and signify-ts's current tests pin,
with provenance. fiki verifies neither dialect's legacy form; the legacy table is checked here
only as pure Ed25519 over the base it states, so a transcription error cannot reach the file.
legacy.json's multi-key cases (keri_vectors_format 7, ``this.i`` @2wdtp6md, and 8, @7ve9r2c6)
are generated here, signed with seeded keys over a legacy base, and checked against their key
state's own list of keys that alone satisfy its threshold (profile section 8), never against a
legacy verifier.

The files are copied verbatim into keripy and signify-ts, where this repository's this.i ids and
tick ids resolve to nothing, so the text written into them cites profile sections instead
(@7ve9r2c6). The ids stay in this file's comments.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import sys
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "py" / "src"))

import http_sfv  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from fiki import (  # noqa: E402
    DEFAULT_COVERED,
    REQUEST_MINIMUM,
    RESPONSE_MINIMUM,
    Key,
    Request,
    req,
    response_signature_base,
    sign_request,
    sign_response,
    signature_base,
    verify_request,
    verify_response,
    verifying_key,
)
from fiki.base import component  # noqa: E402
from fiki.errors import FikiError, UnsupportedSigner  # noqa: E402
from fiki.messages import content_digest  # noqa: E402

# The contract's own format number, separate from vectors_format (@8vwrexxc, @4fhrre0m). Format 4
# is the 0.8.0 cross-port sweep (@5zrf8gjk): the keyid order, the empty-Signature 401,
# Content-Length's whitespace, weak and aliased B keyids, and the request-digest response case.
# Format 5 is the review's remaining profile cases; format 6 rides with vectors_format 4
# (@646un6k8): a non-byte-sequence Signature member and a keyid the library must refuse itself.
# Format 7 is profile version 1.1 (@2wdtp6md): legacy.json's multi-key cases and their key states.
# Format 8 is profile version 1.2 (@7ve9r2c6): legacy mode's sufficient_keys, and a case for each
# disagreement the 2026-11-11 review found.
KERI_VECTORS_FORMAT = 8

# fiki's classes to the profile's section 9 codes. The vectors name codes, never classes, because
# signify-ts will not reproduce fiki's taxonomy. MissingKey has no code of its own in the profile:
# keyid is REQUIRED there, so its absence is a malformed Signature-Input.
CODES = {
    "MissingSignature": "missing-signature",
    "MissingSignatureInput": "missing-signature-input",
    "MalformedSignature": "malformed-signature",
    "MalformedSignatureInput": "malformed-signature-input",
    "MissingKey": "malformed-signature-input",
    "MalformedSignatureLabel": "malformed-signature-label",
    "MissingSignatureLabel": "missing-signature-label",
    "MalformedSignatureValue": "malformed-signature-value",
    "DuplicateComponent": "duplicate-component",
    "UnsupportedComponent": "unsupported-component",
    "InsufficientCoverage": "insufficient-coverage",
    "MalformedKey": "malformed-key",
    "UnknownKey": "unknown-key",
    "UnsupportedSigner": "unsupported-signer",
    "UnsupportedAlgorithm": "unsupported-algorithm",
    "MissingComponent": "missing-component",
    "SignatureMismatch": "signature-mismatch",
    "SignatureTooOld": "signature-stale",
    "SignatureExpired": "signature-expired",
    "MalformedDigest": "malformed-digest",
    "DigestMismatch": "digest-mismatch",
    "UncoveredBody": "uncovered-body",
    "Unauthenticated": "unauthenticated",
}

# Section 9's codes in the order its numbered list first reaches them (profile 1.2). Two recur
# later in that list -- insufficient-coverage at the body stage, malformed-key for a resolved
# key -- and the file's codes_rule says so. mode-mismatch cases are carried as data: fiki has no
# legacy parser, so it cannot tell a legacy header from a malformed one.
PROFILE_CODES = [
    "unauthenticated", "missing-signature", "missing-signature-input", "malformed-signature",
    "mode-mismatch", "malformed-signature-input", "malformed-signature-label",
    "missing-signature-label", "malformed-signature-value", "duplicate-component",
    "unsupported-component", "insufficient-coverage", "malformed-key", "unknown-key",
    "unsupported-signer", "unsupported-algorithm", "missing-component", "signature-mismatch",
    "signature-stale", "signature-expired", "malformed-digest", "digest-mismatch",
    "uncovered-body",
]

MAX_AGE = 300
SKEW = 60
AT = 1700000000
LABEL = "signify"
HOST = "https://keria.example.com"
BODY = '{"name": "alice", "salt": "0ACDEyMzQ1Njc4OWFiY2RlZg"}'

PROFILE = {
    "title": "KERI profile of RFC 9421 HTTP Message Signatures",
    "version": "1.2",
    "date": "2026-11-12",
    "where": "https://github.com/bakobo/fiki/blob/keri-profile-v1.2/docs/keri-profile.md",
    "rules": "Canonical mode only. Refusals are named by the profile's section 9 codes. A "
             "verifier runs its checks in section 9's order and reports the first that fails, so "
             "every case has exactly one correct code. A refusal case carries one defect unless "
             "its note names two, and then it pins which of them section 9's order reports.",
}

POLICY = {
    "max_age": MAX_AGE,
    "skew": SKEW,
    "request_minimum": [str(component(spec)) for spec in REQUEST_MINIMUM],
    "response_minimum": [str(component(spec)) for spec in RESPONSE_MINIMUM],
    "body_rule": "Profile sections 3 and 9. A REQUEST's headers announce a body when it carries "
                 "any Transfer-Encoding or a Content-Length other than a plain zero (one or more "
                 "ASCII digits once SP and HTAB are trimmed, of value zero); a body so announced "
                 "without a covered content-digest is insufficient-coverage at the covered list. "
                 "A non-empty request body no header announced is insufficient-coverage at the "
                 "body stage, after the signature and freshness checks. A RESPONSE has a body "
                 "when it has content, judged at the covered list; its Content-Length is not "
                 "evidence, since a HEAD or 304 response announces a length it does not send. A "
                 "response to a request whose content was non-empty must also cover "
                 "\"content-digest\";req; the request's headers do not count there, since both "
                 "sides hold the whole request by the time a response is signed or verified.",
    "freshness": "Profile section 6: refuse created < now - max_age - skew or created > now + "
                 "skew as signature-stale, then expires < now - skew as signature-expired. Each "
                 "case gives the now it assumes, in seconds since the epoch; where it has a "
                 "fractional part, the verifier rounds it down first.",
    "case_policy": "A case may carry a policy object whose fields extend this one: "
                   "expected_keyid, the AID a client expects a response from (profile R1); "
                   "authorities, the @authority values a verifier serves (profile section 3), "
                   "whose presence also makes @authority required: a request that does not "
                   "cover it is insufficient-coverage.",
}

ENCODING = {
    "body": "The content as a UTF-8 string, after any transfer coding is removed; null means no "
            "body is handed to the verifier, which is how a case tests what the headers alone "
            "announce.",
    "headers": "Field names as a sender would write them; a verifier matches them "
               "case-insensitively. Each value is one field line.",
    "covered": "Component identifiers in their RFC 8941 serialized form, as they appear in "
               "Signature-Input: \"@method\", \"@path\";req.",
    "effective_key": "The raw 32-byte Ed25519 public key, base64url without padding.",
    "signature": "The raw 64-byte Ed25519 signature, standard base64, as inside the Signature "
                 "header's colons.",
    "seed_hex": "The 32-byte Ed25519 seed, hex, so a signer can reproduce every signature; "
                "Ed25519 is deterministic.",
}

KEYS_RULE = (
    "Profile R1. A keyid is a well-formed AID when it is the canonical qb64 spelling of one of "
    "keripy's PreDex prefix codes: B, D, E, F, G, H and I over 32 bytes; 0D, 0E, 0F and 0G over "
    "64; 1AAA, 1AAB, 1AAI and 1AAJ over 33; 1AAC and 1AAD over 57; 1AAE over 114. The bytes "
    "are padded in front with zero bytes to a multiple of three, base64url-encoded, and the "
    "code written over the characters the padding became, so re-encoding gives back the keyid "
    "exactly. Any other keyid is malformed-key. A B keyid yields its key from the prefix, and "
    "the verifier asks no key store about it, so a B keyid this table does not list still "
    "verifies; that key must be a valid point of the prime-order subgroup or the keyid is "
    "malformed-key. A non-transferable code other than B is unsupported-algorithm. Every other "
    "keyid resolves through the key state the verifier holds, which this table stands in for: "
    "absent from the table is unknown-key, an entry whose effective_key is null is "
    "unsupported-signer, and an entry marked weak_key holds a key that is not a valid "
    "prime-order point, which is malformed-key as it is resolved. key_state is the state an "
    "implementation with a KERI stack reduces itself (profile R4): the current signing keys as "
    "qb64 verfers, and the signing threshold in keripy's form. The effective key is the one key "
    "that satisfies the threshold alone, when exactly one does."
)


def qb64(code: str, raw: bytes) -> str:
    """A one-character CESR code over 32 raw bytes: the arithmetic of fiki's own B lens."""
    return code + base64.urlsafe_b64encode(b"\x00" + raw).decode("ascii")[1:]


def raw_key(key: Key) -> bytes:
    return verifying_key(key.aid).public_bytes_raw()


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def synthetic_aid(label: str) -> str:
    """A well-formed E-code (Blake3-256 digest) AID whose KEL the vectors posit.

    Not the digest of a real inception event: computing one needs a KERI stack, which fiki does
    not have (@07wstqk7). A verifier resolves it through its key table and never inspects it.
    """
    return qb64("E", hashlib.sha256(f"fiki keri vectors: {label}".encode()).digest())


def seeded(n: int) -> Key:
    return Key.from_seed(bytes(range(n, n + 32)))


NON_TRANSFERABLE = seeded(0)
CONTROLLER = seeded(2)
AGENT = seeded(3)
INCEPTION = seeded(4)
ROTATED = seeded(5)
PASSCODE_NEW = seeded(6)
PRIOR_NEXT = seeded(7)
GROUP = [seeded(8), seeded(9), seeded(10)]
UNLISTED = seeded(13)

B_AID = NON_TRANSFERABLE.aid
CONTROLLER_AID = synthetic_aid("controller")
AGENT_AID = synthetic_aid("agent")
D_AID = qb64("D", raw_key(INCEPTION))
UNKNOWN_AID = synthetic_aid("a controller this verifier holds no KEL for")
PASSCODE_AID = synthetic_aid("a Signify controller after a passcode rotation")
EITHER_AID = synthetic_aid("either of two keys suffices")
TWO_OF_THREE_AID = synthetic_aid("two of three keys")
WEAK_KEY_AID = synthetic_aid("a KEL whose current key is of mixed order")

SIGNERS = {B_AID: NON_TRANSFERABLE, CONTROLLER_AID: CONTROLLER, AGENT_AID: AGENT, D_AID: ROTATED,
           PASSCODE_AID: PASSCODE_NEW, EITHER_AID: GROUP[0], TWO_OF_THREE_AID: GROUP[0],
           WEAK_KEY_AID: CONTROLLER}


def verfer(key: Key) -> str:
    return qb64("D", raw_key(key))


def transferable(keyid, keys, threshold, effective, note, **extra):
    return {"keyid": keyid, "kind": "transferable",
            "effective_key": None if effective is None else b64url(
                effective if isinstance(effective, bytes) else raw_key(effective)),
            "seed_hex": SIGNERS[keyid].seed.hex(),
            "key_state": {"keys": [key if isinstance(key, str) else verfer(key) for key in keys],
                          "threshold": threshold},
            **extra, "note": note}


def mixed_order(key: Key) -> bytes:
    """key's public point plus a point of order 8, built with RFC 8032's own code: on the curve,
    not of small order, and outside the prime-order subgroup (profile R1, tick 47bl)."""
    sys.path.insert(0, str(ROOT / "vectors"))
    import rfc8032  # noqa: PLC0415

    point = rfc8032.point_decompress(raw_key(key))
    for n in range(1, 1000):
        candidate = rfc8032.point_decompress(hashlib.sha256(b"fiki-torsion-%d" % n).digest())
        if candidate is None:
            continue
        torsion = rfc8032.point_mul(rfc8032.q, candidate)
        identity = (0, 1, 1, 0)
        if not rfc8032.point_equal(rfc8032.point_mul(4, torsion), identity):
            mixed = rfc8032.point_add(point, torsion)
            assert not rfc8032.point_equal(rfc8032.point_mul(rfc8032.q, mixed), identity)
            assert not rfc8032.point_equal(rfc8032.point_mul(8, mixed), identity)
            return rfc8032.point_compress(mixed)
    raise SystemExit("no point of order 8 found")


MIXED = mixed_order(NON_TRANSFERABLE)
WEAK_RESOLVED = mixed_order(CONTROLLER)


KEYS = [
    {"keyid": B_AID, "kind": "non-transferable",
     "effective_key": b64url(raw_key(NON_TRANSFERABLE)), "seed_hex": NON_TRANSFERABLE.seed.hex(),
     "note": "Ed25519N. The verifier derives the key from the prefix itself and holds no KEL."},
    transferable(CONTROLLER_AID, [CONTROLLER], "1", CONTROLLER,
                 "A controller with one current signing key. The AID is synthetic: a "
                 "well-formed E code, not the digest of a real inception event."),
    transferable(AGENT_AID, [AGENT], "1", AGENT,
                 "An agent with one current signing key; it signs the responses. Synthetic "
                 "like the controller's."),
    transferable(D_AID, [ROTATED], "1", ROTATED,
                 "A basic transferable prefix after one rotation. Decoding the prefix yields "
                 "embedded_key, the INCEPTION key; the current key comes only from the KEL "
                 "(profile R1). A verifier that decodes a D keyid as a key accepts a "
                 "rotated-away key.",
                 embedded_key=b64url(raw_key(INCEPTION)),
                 embedded_seed_hex=INCEPTION.seed.hex()),
    transferable(PASSCODE_AID, [PASSCODE_NEW, PRIOR_NEXT], ["1", "0"], PASSCODE_NEW,
                 "A Signify controller after its passcode is rotated: keys [new, prior-next] "
                 "and threshold ['1','0'], so only the first key satisfies it alone, and that "
                 "key signs (profile R4)."),
    transferable(EITHER_AID, GROUP[:2], "1", None,
                 "Threshold 1 over two keys: either alone suffices, so there is no single "
                 "effective signer and the signature names no key index (profile R4). The "
                 "vectors' messages for this keyid are signed by the first key."),
    transferable(TWO_OF_THREE_AID, GROUP, "2", None,
                 "A 2-of-3 group: no one key suffices (profile R4). The vectors' messages for "
                 "this keyid are signed by the first key."),
    transferable(WEAK_KEY_AID, [qb64("D", WEAK_RESOLVED)], "1", WEAK_RESOLVED,
                 "A KEL whose current key is of mixed order: the controller's key plus a point of "
                 "order 8 (profile R1). No seed yields it, so seed_hex is the key the messages "
                 "for this keyid were signed with, which the verifier never reaches.",
                 weak_key=True),
]


def effective_signer(keys: list[str], threshold) -> str | None:
    """Profile R4: the one current key that satisfies the signing threshold alone, or None.

    keys are qb64 verfers and threshold is in keripy's form: a hex integer string for M of N, or a
    list of fractional weights. Only the forms the vectors use are read; anything else aborts.
    """
    if isinstance(threshold, str):
        alone = list(keys) if int(threshold, 16) == 1 else []
    elif len(threshold) == len(keys) and all(isinstance(w, str) for w in threshold):
        alone = [key for key, weight in zip(keys, threshold) if Fraction(weight) >= 1]
    else:
        raise SystemExit(f"a threshold the vectors do not use: {threshold!r}")
    return alone[0] if len(alone) == 1 else None


def raw_of(verfer_qb64: str) -> bytes:
    return base64.urlsafe_b64decode("A" + verfer_qb64[1:])[1:]


for _entry in KEYS:
    if "key_state" in _entry and not _entry.get("weak_key"):
        _found = effective_signer(_entry["key_state"]["keys"], _entry["key_state"]["threshold"])
        if (None if _found is None else b64url(raw_of(_found))) != _entry["effective_key"]:
            raise SystemExit(f"{_entry['keyid']}: effective_key disagrees with its key_state")


def padding_bit_alias(aid: str) -> str:
    """The same 32 bytes spelled with bit 4 of the second character set, as py/tests/test_keys.py
    builds it: that bit lands in the pad byte the code character replaced."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return aid[0] + alphabet[alphabet.index(aid[1]) ^ 16] + aid[2:]


PREFIX_CODES = {
    "B": 32, "D": 32, "E": 32, "F": 32, "G": 32, "H": 32, "I": 32,
    "0D": 64, "0E": 64, "0F": 64, "0G": 64,
    "1AAA": 33, "1AAB": 33, "1AAI": 33, "1AAJ": 33,
    "1AAC": 57, "1AAD": 57, "1AAE": 114,
}


def cesr(code: str, raw: bytes) -> str:
    """Any PreDex code over its raw bytes: zero bytes in front to a multiple of three, base64url,
    and the code over the characters the padding became."""
    pad = (3 - len(raw) % 3) % 3
    return code + base64.urlsafe_b64encode(bytes(pad) + raw).decode("ascii")[pad:]


def well_formed_aid(keyid: str) -> bool:
    """KEYS_RULE's test, which the keys table is checked against. The resolver does not apply it:
    a library must (fiki @7w7nv94j, @37rktct3)."""
    for code, size in PREFIX_CODES.items():
        if not keyid.startswith(code):
            continue
        pad = (3 - size % 3) % 3
        try:
            decoded = base64.b64decode("A" * pad + keyid[len(code):], altchars=b"-_",
                                       validate=True)
        except ValueError:
            return False
        # Canonical only: a non-zero bit in the pad bytes the code replaced is a second spelling
        # of the same bytes, and a B keyid spelled that way would alias the same key.
        return len(decoded) == pad + size and cesr(code, decoded[pad:]) == keyid
    return False


def resolver(keys: list[dict]):
    """What a KERI verifier's key lookup does, for a keys table: authoritative, never a decode.

    It knows key state and nothing else (since keri_vectors_format 6, fiki @7w7nv94j): it returns a key,
    says the keyid is unknown, or says its signer is unsupported. A keyid that is not a
    well-formed AID never reaches it, because the library refuses it first, and the vectors'
    keyid-not-an-aid and padding-bit-alias cases check that the library does. Since format 8 it
    knows nothing of B keyids either (@37rktct3): the library takes their key from the prefix
    and never asks, so a library that did ask would find no key and fail the accept cases.
    """
    table = {entry["keyid"]: entry for entry in keys if entry["kind"] == "transferable"}

    def resolve(keyid: str):
        entry = table.get(keyid)
        if entry is None:
            return None
        if entry["effective_key"] is None:
            raise UnsupportedSigner(
                f'The key state of "{keyid}" has no single key that satisfies its threshold.',
                keyid=keyid,
            )
        return base64.urlsafe_b64decode(entry["effective_key"] + "=")

    return resolve


resolve = resolver(KEYS)


def key_for(keyid: str, keys=KEYS) -> bytes:
    """The key a signature under keyid is checked with: the prefix's for B, else the table's."""
    if keyid.startswith("B"):
        return base64.urlsafe_b64decode("A" + keyid[1:])[1:]
    return resolver(keys)(keyid)


def header(about: str) -> dict:
    return {
        "about": about,
        "keri_vectors_format": KERI_VECTORS_FORMAT,
        "generated_by": "vectors/keri/generate.py",
        "profile": PROFILE,
        "encoding": ENCODING,
    }


def policy_header(about: str) -> dict:
    return {**header(about), "policy": POLICY, "keys_rule": KEYS_RULE, "keys": KEYS}


def nonce(case_id: str) -> str:
    """128 bits, as the profile asks a signer to emit — deterministic here so the bytes are fixed."""
    return b64url(hashlib.sha256(case_id.encode()).digest()[:16])


def body_bytes(body: str | None) -> bytes | None:
    return None if body is None else body.encode("utf-8")


# --- signing ---

def signed_request(case_id, *, keyid=CONTROLLER_AID, key=None, method="POST",
                   url=f"{HOST}/identifiers", headers=None, body=BODY, covered=None,
                   created=AT, expires=None, emit_alg=True, with_nonce=True,
                   minimum=REQUEST_MINIMUM, unchecked=False):
    """A request signed as a Signify client would sign it: refusing, as the profile's signer
    does, to cover less than the minimum set unless a case deliberately asks for that.

    ``unchecked`` signs over the base directly, for a Content-Digest the body contradicts, which
    sign_request refuses to sign (@5zrf8gjk) and a verifier must still refuse. The bytes are the
    ones sign_request emits for the same inputs: the same base and parameter order, alg included.
    """
    key = key or SIGNERS[keyid]
    sending = dict(headers or {})
    if unchecked:
        covered = list(covered or DEFAULT_COVERED) + ["content-digest"]
        base = signature_base(method=method, url=url, headers=sending, covered=covered,
                              created=created, keyid=keyid, alg="ed25519",
                              nonce=nonce(case_id) if with_nonce else None)
        attach(sending, base, key.sign(base))
    elif emit_alg:
        sending.update(sign_request(
            key=key, method=method, url=url, headers=dict(sending), body=body_bytes(body),
            covered=covered, created=created, expires=expires, label=LABEL,
            nonce=nonce(case_id) if with_nonce else None, keyid=keyid, minimum=minimum,
        ))
    else:
        # sign_request always emits alg, so the absent-alg case is assembled from the base.
        covered = list(covered or DEFAULT_COVERED)
        if body is not None:
            sending["Content-Digest"] = content_digest(body_bytes(body))
            covered.append("content-digest")
        base = signature_base(method=method, url=url, headers=sending, covered=covered,
                              created=created, keyid=keyid,
                              nonce=nonce(case_id) if with_nonce else None)
        attach(sending, base, key.sign(base))
    return {"method": method, "url": url, "headers": sending, "body": body}


def attach(headers: dict, base: bytes, signature: bytes) -> None:
    params = base.decode("utf-8").rsplit('"@signature-params": ', 1)[1]
    headers["Signature-Input"] = f"{LABEL}={params}"
    headers["Signature"] = f"{LABEL}=:{base64.b64encode(signature).decode('ascii')}:"


def signed_response(case_id, request, *, status=200, body='{"done": true}', headers=None,
                    covered=None, key=None, keyid=AGENT_AID, minimum=RESPONSE_MINIMUM):
    sending = dict(headers or {})
    sending.update(sign_response(
        key=key or SIGNERS[keyid], status=status, request=as_request(request),
        headers=dict(sending), body=body_bytes(body), covered=covered, created=AT, label=LABEL,
        nonce=nonce(case_id), keyid=keyid, minimum=minimum,
    ))
    return {"status": status, "headers": sending, "body": body}


def as_request(message) -> Request:
    return Request(method=message["method"], url=message["url"], headers=message["headers"],
                   body=body_bytes(message["body"]))


# --- running fiki as the verifier the vectors describe ---

def verify(request, response=None, *, now, policy=None, keys=KEYS):
    """Verify as a KERI verifier would, under the file's policy extended by the case's."""
    policy = {**POLICY, **(policy or {})}
    # fiki takes whole seconds; the profile rounds a fractional clock down (section 6).
    common = dict(max_age=policy["max_age"], skew=policy["skew"], now=math.floor(now),
                  resolve=resolver(keys), expected_keyid=policy.get("expected_keyid"))
    if response is not None:
        return verify_response(
            status=response["status"], headers=response["headers"],
            body=body_bytes(response["body"]), request=as_request(request),
            minimum=policy["response_minimum"], **common,
        )
    authorities = policy.get("authorities")
    return verify_request(
        method=request["method"], url=request["url"], headers=request["headers"],
        body=body_bytes(request["body"]), minimum=policy["request_minimum"],
        authorities=None if authorities is None else set(authorities), **common,
    )


def expected_base(request, response=None, *, keys=KEYS) -> tuple[str, str]:
    """The base a signer builds from the parameters its Signature-Input carries, and its signature.

    Rebuilt through fiki's signing-side base functions and re-signed, then compared with the
    signature on the message, so the base an accept case publishes is the one that was signed.
    """
    message = response or request
    parsed = http_sfv.Dictionary()
    parsed.parse(message["headers"]["Signature-Input"].encode("utf-8"))
    ((_, inner),) = parsed.items()
    params = dict(inner.params)
    kwargs = dict(covered=list(inner), created=params["created"], keyid=params["keyid"],
                  alg=params.get("alg"), expires=params.get("expires"),
                  nonce=params.get("nonce"), tag=params.get("tag"))
    if response is not None:
        base = response_signature_base(status=response["status"], headers=response["headers"],
                                       request=as_request(request), **kwargs)
    else:
        base = signature_base(method=request["method"], url=request["url"],
                              headers=request["headers"], **kwargs)
    signature = message["headers"]["Signature"].split("=", 1)[1].strip(":")
    Ed25519PublicKey.from_public_bytes(key_for(params["keyid"], keys)).verify(
        base64.b64decode(signature), base
    )
    return base.decode("utf-8"), signature


def accept(case_id, request, response=None, *, now=AT + 30, policy=None, note):
    verdict = verify(request, response, now=now, policy=policy)
    base, signature = expected_base(request, response)
    case = {"id": case_id, "note": note, "request": request}
    if response is not None:
        case["response"] = response
    if policy:
        case["policy"] = policy
    case["now"] = now
    case["expected"] = {
        "keyid": verdict.keyid,
        "covered": [str(component(spec)) for spec in verdict.covered],
        "base": base,
        "signature": signature,
    }
    return case


PADDING_WHY = ("fiki's own vectors refuse a byte sequence without its padding, so fiki "
               "cannot verify this case without failing its own contract. The generator signed "
               "and verified the padded message, then removed the padding; nothing else differs.")


def unpadded_signature(case):
    """An accept case with the padding taken off its Signature value (profile section 5)."""
    request = case["request"]
    value = request["headers"]["Signature"]
    label, inside = value.split("=:", 1)
    stripped = f"{label}=:{inside.rstrip(':').rstrip('=')}:"
    assert stripped != value
    signature = case["expected"]["signature"].rstrip("=")
    return {**case, "request": {**request, "headers": {**request["headers"],
                                                       "Signature": stripped}},
            "expected": {**case["expected"], "signature": signature},
            "verified_by_fiki": False, "why": PADDING_WHY}


def unpadded_digest(case_id, *, note):
    """A request whose covered Content-Digest has no padding, signed over that value as sent.

    fiki would refuse the digest, so the generator checks what it can without fiki's verifier:
    the base the Signature-Input describes is the one signed, and the digest re-padded is the
    body's own sha-256.
    """
    digest = content_digest(BODY.encode())
    unpadded = digest.replace("=:", "\0", 1).replace("=", "").replace("\0", "=:", 1)
    assert unpadded != digest and unpadded.count("=") == 1
    request = signed_request(case_id, headers={"Content-Digest": unpadded}, unchecked=True)
    base, signature = expected_base(request)
    value = unpadded.split("=:", 1)[1].rstrip(":")
    assert base64.b64decode(value + "=" * (-len(value) % 4)) == hashlib.sha256(
        BODY.encode()).digest()
    covered = [str(component(spec)) for spec in DEFAULT_COVERED] + ['"content-digest"']
    return {"id": case_id, "note": note, "request": request, "now": AT + 30,
            "expected": {"keyid": CONTROLLER_AID, "covered": covered, "base": base,
                         "signature": signature},
            "verified_by_fiki": False, "why": PADDING_WHY}


def refuse(case_id, error, request, response=None, *, now=AT + 30, policy=None, note,
           verified_by_fiki=True, why=None):
    if verified_by_fiki:
        try:
            verify(request, response, now=now, policy=policy)
        except FikiError as ex:
            got = CODES[type(ex).__name__]
        else:
            got = "(accepted)"
        if got != error:
            raise SystemExit(f"{case_id}: the case names {error} and fiki reports {got}")
    case = {"id": case_id, "kind": "response" if response is not None else "request",
            "note": note, "request": request}
    if response is not None:
        case["response"] = response
    if policy:
        case["policy"] = policy
    case["now"] = now
    case["error"] = error
    if not verified_by_fiki:
        case["verified_by_fiki"] = False
        case["why"] = why
    return case


def tamper(message, header, old, new):
    headers = dict(message["headers"])
    if old not in headers[header]:
        raise SystemExit(f"cannot tamper: {old!r} is not in {header}")
    headers[header] = headers[header].replace(old, new, 1)
    return {**message, "headers": headers}


def without(message, *names):
    return {**message, "headers": {k: v for k, v in message["headers"].items() if k not in names}}


# --- the files ---

RFC_SEED = base64.urlsafe_b64decode("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU" + "=")


def rfc9421():
    request = {
        "method": "POST",
        "url": "https://example.com/foo?param=Value&Pet=dog",
        "headers": {
            "Host": "example.com",
            "Date": "Tue, 20 Apr 2021 02:07:55 GMT",
            "Content-Type": "application/json",
            "Content-Digest": "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+Ab"
                              "wAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
            "Content-Length": "18",
        },
        "body": '{"hello": "world"}',
    }
    covered = ["date", "@method", "@path", "@authority", "content-type", "content-length"]
    base = signature_base(method=request["method"], url=request["url"],
                          headers=request["headers"], covered=covered, created=1618884473,
                          keyid="test-key-ed25519")
    signature = base64.b64encode(Key.from_seed(RFC_SEED).sign(base)).decode("ascii")
    case = {
        "id": "rfc-9421-b-2-6",
        "note": "RFC 9421 Appendix B.2.6: the B.2 test request signed with the B.1.4 Ed25519 key. "
                "Reproduce the base and the signature byte for byte. Neither the minimum covered "
                "set nor the AID keyid applies; this pins the signature base builder against "
                "something no party to the profile wrote.",
        "request": request,
        "seed_hex": RFC_SEED.hex(),
        "public_key": b64url(raw_key(Key.from_seed(RFC_SEED))),
        "label": "sig-b26",
        "covered": covered,
        "created": 1618884473,
        "keyid": "test-key-ed25519",
        "expected": {"base": base.decode("utf-8"), "signature": signature},
    }
    return {**header("RFC 9421's own Ed25519 example, reproduced."), "cases": [case]}


def requests():
    cases = [
        accept("get-with-query", signed_request(
            "get-with-query", method="GET", url=f"{HOST}/identifiers?type=rot&last=5", body=None),
            note="The default signer set: @method, @authority, @path, @query."),
        accept("get-without-query", signed_request(
            "get-without-query", method="GET", url=f"{HOST}/identifiers", body=None),
            note="@query is a bare question mark when the target has no query."),
        accept("post-with-content-digest", signed_request("post-with-content-digest"),
               note="A body is covered by a sha-256 Content-Digest."),
        accept("post-with-empty-body", signed_request(
            "post-with-empty-body", body="", headers={"Content-Length": "0"}),
            note="A covered content-digest on an empty body is the digest of the empty string."),
        accept("digest-with-an-unknown-algorithm-member", signed_request(
            "digest-with-an-unknown-algorithm-member",
            headers={"Content-Digest": "x-unknown=:AAAA:, " + content_digest(BODY.encode())}),
            note="RFC 9530: an algorithm the verifier does not recognize is ignored, and it comes "
                 "first so a verifier that checks only the first member fails."),
        accept("digest-with-two-recognized-members", signed_request(
            "digest-with-two-recognized-members",
            headers={"Content-Digest": content_digest(BODY.encode()) + ", sha-512=:"
                     + base64.b64encode(hashlib.sha512(BODY.encode()).digest()).decode() + ":"}),
            note="Every recognized member must match, and both do."),
        accept("chunked-body-with-content-digest", signed_request(
            "chunked-body-with-content-digest", headers={"Transfer-Encoding": "chunked"}),
            note="A chunked body is covered like any other; body is the de-chunked content."),
        accept("lowercase-method", signed_request(
            "lowercase-method", method="post"),
            note="RFC 9421 section 2.2.1: @method is the method as sent, with no case "
                 "transformation. Browsers' fetch() uppercases standard methods on the wire."),
        accept("path-with-a-colon", signed_request(
            "path-with-a-colon", method="GET", url=f"{HOST}/identifiers/a:b", body=None),
            note="Profile O1: hio re-encodes ':' as %3A, so a KERIA that rebuilds @path from "
                 "hio's path fails this. @path is the path as sent."),
        accept("path-with-an-encoded-tilde", signed_request(
            "path-with-an-encoded-tilde", method="GET", url=f"{HOST}/identifiers/%7Ebob",
            body=None),
            note="Profile O1: hio decodes %7E to '~' and does not re-encode it. @path keeps "
                 "the percent-encoding as sent."),
        accept("non-transferable-keyid", signed_request(
            "non-transferable-keyid", keyid=B_AID, method="GET",
            url=f"{HOST}/identifiers?type=rot", body=None),
            note="A B keyid yields its key directly from the prefix; no KEL."),
        accept("transferable-aid-keyid", signed_request(
            "transferable-aid-keyid", keyid=CONTROLLER_AID),
            note="An E keyid: the key comes from the KEL the verifier holds, which the keys "
                 "table stands in for."),
        accept("basic-transferable-keyid-after-rotation", signed_request(
            "basic-transferable-keyid-after-rotation", keyid=D_AID),
            note="A D keyid signed by its CURRENT key after rotation, resolved through the KEL. "
                 "Decoding the prefix would give the inception key and refuse this."),
        accept("absent-alg", signed_request("absent-alg", emit_alg=False),
               note="alg is optional on the wire; when absent the algorithm is the one the "
                    "resolved key implies."),
        accept("without-nonce", signed_request("without-nonce", with_nonce=False),
               note="nonce is optional on the wire and never checked."),
        accept("stale-boundary-inside", signed_request("stale-boundary-inside"),
               now=AT + MAX_AGE + SKEW,
               note="created = now - max_age - skew exactly, which is not earlier than it."),
        accept("future-boundary-inside", signed_request("future-boundary-inside"),
               now=AT - SKEW, note="created = now + skew exactly."),
        accept("expires-boundary-inside", signed_request(
            "expires-boundary-inside", expires=AT + 100), now=AT + 100 + SKEW,
            note="expires = now - skew exactly."),
        accept("passcode-rotated-controller", signed_request(
            "passcode-rotated-controller", keyid=PASSCODE_AID),
            note="Profile R4: keys [new, prior-next] with threshold ['1','0'] has one effective "
                 "signer, the first key, and it signed."),
        accept("content-length-zero-padded-with-sp-and-htab", signed_request(
            "content-length-zero-padded-with-sp-and-htab", method="GET",
            url=f"{HOST}/identifiers", body=None, headers={"Content-Length": " \t0\t "}),
            note="SP and HTAB are the only optional whitespace around a field value, so this "
                 "is a Content-Length of zero and no body (profile section 3)."),
        accept("authority-in-the-served-set", signed_request(
            "authority-in-the-served-set", url="/identifiers",
            headers={"Host": "keria.example.com"}),
            policy={"authorities": ["keria.example.com"]},
            note="A covered @authority the verifier serves, rebuilt from Host."),
        # keri_vectors_format 8, profile 1.2 (@7ve9r2c6).
        accept("non-transferable-keyid-with-no-key-state", signed_request(
            "non-transferable-keyid-with-no-key-state", keyid=UNLISTED.aid, key=UNLISTED,
            method="GET",
            url=f"{HOST}/identifiers?type=rot", body=None),
            note="A B keyid the keys table does not list, as a verifier holding no key state "
                 "at all would see it: the key is the prefix's, and no key store is asked "
                 "(profile R1)."),
        accept("fractional-clock-is-rounded-down", signed_request(
            "fractional-clock-is-rounded-down"), now=AT + MAX_AGE + SKEW + 0.5,
            note="The clock reads half a second past the stale boundary; rounded down to whole "
                 "seconds it is exactly on it, which is inside (profile section 6)."),
        unpadded_signature(accept("signature-without-padding", signed_request(
            "signature-without-padding", method="GET", url=f"{HOST}/identifiers?type=rot",
            body=None),
            note="The Signature's byte sequence without its '=' padding, which a verifier "
                 "accepts (profile section 5, RFC 8941 section 4.2.7).")),
        unpadded_digest("content-digest-without-padding",
                        note="The covered Content-Digest's byte sequence without its '=' "
                             "padding: accepted, and the digest still matches (profile section "
                             "5). The base carries the field value as sent, unpadded."),
    ]
    return {**policy_header("Signed requests a canonical verifier must ACCEPT, with the base."),
            "verify_only": ["digest-with-an-unknown-algorithm-member",
                            "digest-with-two-recognized-members", "signature-without-padding",
                            "content-digest-without-padding"],
            "verify_only_why": "These cases carry a Content-Digest with a member a sha-256-only "
                               "signer does not emit, or a byte sequence without the padding a "
                               "signer emits, so a signer cannot reproduce their headers byte "
                               "for byte. Verify them; do not expect to sign them.",
            "verified_by_fiki_rule": "A case marked verified_by_fiki false is one fiki carries "
                                     "as data, for the reason its why gives; every other "
                                     "implementation verifies it.",
            "cases": cases}


def responses():
    post = signed_request("response-to-post:request", url=f"{HOST}/identifiers/alice/events")
    get = signed_request("response-to-get:request", method="GET",
                         url=f"{HOST}/identifiers/alice?include=state", body=None)
    head = signed_request("head-response:request", method="HEAD",
                          url=f"{HOST}/identifiers/alice", body=None)
    agent = {"expected_keyid": AGENT_AID}
    cases = [
        accept("response-to-post", post, signed_response("response-to-post", post),
               policy=agent,
               note="A response binds @status, its own body, and the request's method, path, "
                    "query and content-digest, each marked req."),
        accept("response-to-get", get, signed_response("response-to-get", get), policy=agent,
               note="The request had no body, so no \"content-digest\";req."),
        accept("response-without-a-body", post, signed_response(
            "response-without-a-body", post, status=204, body=None), policy=agent,
            note="A bodiless response covers no content-digest of its own."),
        accept("head-response-with-a-content-length", head, signed_response(
            "head-response-with-a-content-length", head, body=None,
            headers={"Content-Length": "898"}), policy=agent,
            note="A response's body is its content: a HEAD response announces the length of a "
                 "representation it does not send, and needs no content-digest."),
    ]
    return {**policy_header("Signed responses a canonical client must ACCEPT, each with the "
                            "signed request it answers."), "cases": cases}


def refusals():
    post = signed_request("refusal:post")
    get = signed_request("refusal:get", method="GET", url=f"{HOST}/identifiers?type=rot",
                         body=None)
    params_end = f';keyid="{CONTROLLER_AID}"'
    cases = []

    def add(*args, **kwargs):
        cases.append(refuse(*args, **kwargs))

    # Headers present and readable.
    add("no-signature", "missing-signature", without(post, "Signature"),
        note="The Signature header is absent.")
    add("no-signature-input", "missing-signature-input", without(post, "Signature-Input"),
        note="The Signature-Input header is absent.")
    add("unparsable-signature", "malformed-signature", {**post, "headers": {
        **post["headers"], "Signature": "(((("}},
        note="Neither an RFC 8941 dictionary nor the legacy form.")
    add("unparsable-signature-input", "malformed-signature-input", {**post, "headers": {
        **post["headers"], "Signature-Input": "(((("}},
        note="Signature-Input does not parse.")
    add("uppercase-field-name", "malformed-signature-input",
        tamper(post, "Signature-Input", '"content-digest"', '"Content-Digest"'),
        note="A field name parsed from the wire must already be lowercase.")
    add("unknown-signature-parameter", "malformed-signature-input",
        tamper(post, "Signature-Input", params_end, params_end + ';context="x"'),
        note="Only created, expires, nonce, alg, keyid and tag are canonical; context, which "
             "the legacy code parses, is not.")
    add("absent-keyid", "malformed-signature-input",
        tamper(post, "Signature-Input", params_end, ""),
        note="keyid is REQUIRED in the profile.")
    add("two-labels", "malformed-signature-label", tamper(tamper(
        post, "Signature-Input", "",
        "other=" + post["headers"]["Signature-Input"].split("=", 1)[1] + ", "),
        "Signature", "", "other=" + post["headers"]["Signature"].split("=", 1)[1] + ", "),
        note="Canonical mode carries exactly one signature; both headers carry two, under the "
             "same two labels.")
    add("labels-differ", "missing-signature-label",
        tamper(post, "Signature", f"{LABEL}=", "other="),
        note="Signature and Signature-Input name different labels.")
    add("signature-not-64-bytes", "malformed-signature-value", {**post, "headers": {
        **post["headers"], "Signature": f"{LABEL}=:{base64.b64encode(bytes(32)).decode()}:"}},
        note="A 32-byte byte sequence where the 64-byte Ed25519 signature belongs.")
    add("signature-member-not-a-byte-sequence", "malformed-signature", {**post, "headers": {
        **post["headers"], "Signature": f'{LABEL}="not a byte sequence"'}},
        note="Section 9: a Signature member that is not a byte sequence is malformed-signature, "
             "not malformed-signature-value (since keri_vectors_format 6).")

    # The covered list.
    add("duplicate-component", "duplicate-component",
        tamper(post, "Signature-Input", '"@path"', '"@path" "@path"'),
        note="The same component twice.")
    add("unsupported-component-parameter", "unsupported-component",
        tamper(post, "Signature-Input", '"content-digest"', '"content-digest";sf'),
        note="sf is not supported; refused, not ignored.")
    add("unsupported-derived-component", "unsupported-component",
        tamper(post, "Signature-Input", '"@authority"', '"@target-uri"'),
        note="@target-uri is not in the profile's list.")
    add("req-in-a-request", "unsupported-component",
        tamper(post, "Signature-Input", '"@path"', '"@path";req'),
        note="req is valid only in a response.")
    add("query-not-covered", "insufficient-coverage", signed_request(
        "query-not-covered", covered=["@method", "@path", "content-digest"], minimum=None),
        note="Validly signed over too little: @query is in the minimum set.")
    add("content-length-body-without-digest", "insufficient-coverage", signed_request(
        "content-length-body-without-digest", body=None, minimum=None,
        headers={"Content-Length": str(len(BODY.encode()))}),
        note="Content-Length above zero announces a body whose digest is not covered. No body "
             "is handed over: this is the header-time test of section 3.")
    add("chunked-body-without-digest", "insufficient-coverage", signed_request(
        "chunked-body-without-digest", body=None, minimum=None,
        headers={"Transfer-Encoding": "chunked"}),
        note="Any Transfer-Encoding announces a body. No body is handed over.")
    add("negative-content-length", "insufficient-coverage", signed_request(
        "negative-content-length", body=None, minimum=None, headers={"Content-Length": "-1"}),
        note="A Content-Length that is not a plain decimal is not evidence of no body; fail "
             "closed.")
    add("content-length-with-a-no-break-space", "insufficient-coverage", signed_request(
        "content-length-with-a-no-break-space", body=None, minimum=None,
        headers={"Content-Length": "0\u00a0"}),
        note="Only SP and HTAB are trimmed from a Content-Length. A no-break space makes it "
             "something other than a plain decimal, which is not evidence of no body (profile "
             "section 3); a verifier that trims every kind of space reads zero and accepts.")
    add("body-arrived-without-digest", "insufficient-coverage", {**signed_request(
        "body-arrived-without-digest", body=None), "body": BODY},
        note="No header announced a body, and one arrived: the read-time rule of section 3.")
    add("authorities-supplied-but-authority-not-covered", "insufficient-coverage", {
        **signed_request("authorities-supplied-but-authority-not-covered", method="GET",
                         url="https://attacker.example/identifiers?type=rot", body=None,
                         covered=list(REQUEST_MINIMUM)),
        "url": f"{HOST}/identifiers?type=rot"},
        policy={"authorities": ["keria.example.com"]},
        note="Signed for attacker.example over the request minimum, which omits @authority, "
             "and replayed to a verifier that serves only keria.example.com. The signature is "
             "valid over what it covers; a verifier that names the authorities it serves "
             "requires @authority, so this is refused rather than accepted as a cross-host "
             "replay (profile section 3).")

    # The key.
    add("keyid-not-an-aid", "malformed-key", signed_request(
        "keyid-not-an-aid", keyid="not-an-aid", key=CONTROLLER),
        note="The keyid is not a well-formed AID.")
    add("padding-bit-alias-of-a-b-keyid", "malformed-key", signed_request(
        "padding-bit-alias-of-a-b-keyid", keyid=padding_bit_alias(B_AID), key=NON_TRANSFERABLE),
        note="The B keyid with bit 4 of its second character set: the bit lands in the pad byte, "
             "so it decodes to the same 32 bytes and is not the AID's canonical spelling "
             "(keys_rule).")
    add("small-order-b-keyid", "malformed-key", signed_request(
        "small-order-b-keyid", keyid=qb64("B", b"\x01" + bytes(31)), key=NON_TRANSFERABLE),
        note="A well-formed B keyid whose key is the identity point, under which a signature "
             "verifies over any message; refused before the signature is examined.")
    add("unknown-transferable-keyid", "unknown-key", signed_request(
        "unknown-transferable-keyid", keyid=UNKNOWN_AID, key=CONTROLLER),
        note="A well-formed E keyid the verifier holds no KEL for; never a raw key.")
    add("either-of-two-keys", "unsupported-signer", signed_request(
        "either-of-two-keys", keyid=EITHER_AID),
        note="Profile R4: threshold 1 over two keys has no single effective signer.")
    add("two-of-three-keys", "unsupported-signer", signed_request(
        "two-of-three-keys", keyid=TWO_OF_THREE_AID),
        note="Profile R4: a 2-of-3 group has no single effective signer.")
    add("unsupported-algorithm", "unsupported-algorithm",
        tamper(post, "Signature-Input", 'alg="ed25519"', 'alg="rsa-pss-sha512"'),
        note="alg present and not ed25519.")

    # The base and the signature.
    add("covered-field-absent", "missing-component", without(signed_request(
        "covered-field-absent", headers={"X-Request-Id": "7"},
        covered=["@method", "@path", "@query", "x-request-id", "content-digest"]),
        "X-Request-Id"),
        note="A covered field is absent from the message; never skipped.")
    add("rewritten-query", "signature-mismatch", {**get, "url": f"{HOST}/identifiers?type=ixn"},
        note="The query KERIA routes on, rewritten.")
    add("method-case-changed", "signature-mismatch", {**signed_request(
        "method-case-changed", method="post"), "method": "POST"},
        note="Signed as post, received as POST: no case transformation on either side.")
    add("path-reencoded-as-hio-does", "signature-mismatch", {**signed_request(
        "path-reencoded-as-hio-does", method="GET", url=f"{HOST}/identifiers/a:b", body=None),
        "url": f"{HOST}/identifiers/a%3Ab"},
        note="Profile O1 as a refusal: a verifier that substitutes a re-encoded path fails.")
    add("authority-outside-the-served-set", "signature-mismatch", signed_request(
        "authority-outside-the-served-set", url="/identifiers",
        headers={"Host": "other.example.com"}),
        policy={"authorities": ["keria.example.com"]},
        note="Signed for other.example.com and delivered here with its Host intact, so the "
             "rebuilt base verifies; the covered @authority is not one this verifier serves "
             "(profile section 3).")
    add("base-that-cannot-be-built", "signature-mismatch", {**(lambda m: {**m, "headers": {
        **m["headers"], "X-Note": "caf\u00e9"}})(signed_request(
            "base-that-cannot-be-built", headers={"X-Note": "cafe"},
            covered=["@method", "@path", "@query", "x-note", "content-digest"]))},
        note="A covered field value with a non-ASCII character has no one serialization both "
             "sides agree on, so the base cannot be built (profile section 9).")
    add("d-keyid-signed-by-its-inception-key", "signature-mismatch", signed_request(
        "d-keyid-signed-by-its-inception-key", keyid=D_AID, key=INCEPTION),
        note="Signed by the key the D prefix embeds, which has been rotated away. A verifier "
             "that decodes the prefix as a key accepts this; the KEL says otherwise.")

    # Policy.
    add("stale-boundary-outside", "signature-stale", signed_request("stale-boundary-outside"),
        now=AT + MAX_AGE + SKEW + 1, note="created one second before now - max_age - skew.")
    add("future-boundary-outside", "signature-stale", signed_request("future-boundary-outside"),
        now=AT - SKEW - 1, note="created one second after now + skew.")
    add("expires-boundary-outside", "signature-expired", signed_request(
        "expires-boundary-outside", expires=AT + 100), now=AT + 100 + SKEW + 1,
        note="expires one second before now - skew.")

    # The body.
    add("digest-with-no-recognized-algorithm", "malformed-digest", signed_request(
        "digest-with-no-recognized-algorithm", headers={"Content-Digest": "x-unknown=:AAAA:"},
        unchecked=True),
        note="No sha-256 or sha-512 member: an error, not a pass.")
    add("swapped-body", "digest-mismatch", {**post, "body": '{"name": "mallory"}'},
        note="The body does not match its covered digest.")
    add("two-recognized-digests-one-mismatching", "digest-mismatch", signed_request(
        "two-recognized-digests-one-mismatching",
        headers={"Content-Digest": content_digest(BODY.encode()) + ", sha-512=:"
                 + base64.b64encode(hashlib.sha512(b"other").digest()).decode() + ":"},
        unchecked=True),
        note="sha-256 matches and sha-512 does not; every recognized member must match.")

    # keri_vectors_format 5: the review's remaining profile cases (V-S1, V-S5).
    with_created = signature_base(method="GET", url=f"{HOST}/identifiers", headers={},
                                  covered=DEFAULT_COVERED, created=AT, keyid=CONTROLLER_AID,
                                  alg="ed25519", nonce=nonce("absent-created"))
    stripped = with_created.replace(b";created=%d" % AT, b"")
    assert stripped != with_created
    bare = {}
    attach(bare, stripped, CONTROLLER.sign(stripped))
    add("absent-created", "malformed-signature-input",
        {"method": "GET", "url": f"{HOST}/identifiers", "headers": bare, "body": None},
        note="created is REQUIRED in the profile (section 4); refused before the signature is "
             "examined.")
    for name, value in (("content-length", "52"), ("transfer-encoding", "chunked")):
        # Signed with no minimum: the profile's signer would itself refuse a body it cannot cover.
        announced = signed_request(f"lowercase-{name}", body=None, headers={name: value},
                                   minimum=None)
        add(f"lowercase-{name}-body-without-digest", "insufficient-coverage", announced,
            note="Field names match case-insensitively; a verifier that looks this header up by "
                 "its capitalized spelling sees no body and fails open.")

    # Responses.
    asked = signed_request("refusal:asked", url=f"{HOST}/identifiers/alice/events")
    answer = signed_response("refusal:answer", asked)
    agent = {"expected_keyid": AGENT_AID}

    def respond(*args, **kwargs):
        add(*args, policy=agent, **kwargs)

    respond("response-status-altered", "signature-mismatch", asked, {**answer, "status": 201},
        note="The status was changed in transit.")
    respond("response-body-swapped", "digest-mismatch", asked, {**answer, "body": '{"done": false}'},
        note="The response body was replaced.")
    respond("response-to-a-different-path", "signature-mismatch",
        {**asked, "url": f"{HOST}/identifiers/bob/events"}, answer,
        note="A response recorded for one request, replayed against another path.")
    respond("response-missing-a-req-component", "insufficient-coverage", asked, signed_response(
        "response-missing-a-req-component", asked,
        covered=["@status", req("@method"), req("@query"), "content-digest",
                 req("content-digest")], minimum=None),
        note="\"@path\";req is in the response minimum set.")
    respond("response-missing-the-requests-digest", "insufficient-coverage", asked,
        signed_response("response-missing-the-requests-digest", asked,
                        covered=["@status", req("@method"), req("@path"), req("@query"),
                                 "content-digest"], minimum=None),
        note="The request had a body, so the response must cover \"content-digest\";req.")
    respond("response-body-without-digest", "insufficient-coverage", asked, {**signed_response(
        "response-body-without-digest", asked, body=None), "body": '{"done": true}'},
        note="A response body, arriving as content, whose digest is not covered.")
    respond("response-duplicate-req-component", "duplicate-component", asked,
            tamper(answer, "Signature-Input", '"@path";req', '"@path";req "@path";req'),
            note="The same req component twice.")
    respond("response-unsupported-parameter", "unsupported-component", asked,
            tamper(answer, "Signature-Input", '"content-digest";req',
                   '"content-digest";req;sf'),
            note="req is the only supported component parameter; sf beside it is refused.")
    add("response-from-an-unexpected-aid", "unknown-key", asked, signed_response(
        "response-from-an-unexpected-aid", asked, keyid=CONTROLLER_AID), policy=agent,
        note="Validly signed by a key the client knows, but not by the AID it is talking to "
             "(profile R1, section 9).")
    add("response-from-an-unexpected-non-transferable-aid", "unknown-key", asked,
        signed_response("response-from-an-unexpected-non-transferable-aid", asked, keyid=B_AID),
        policy=agent,
        note="Validly signed by a self-certifying B key while the client expects the agent's AID "
             "(profile R1). A verifier that waives expected_keyid for keys that carry themselves "
             "accepts any stranger (since keri_vectors_format 5).")
    respond("unsigned-401", "unauthenticated", asked,
            {"status": 401, "headers": {"Content-Type": "application/json"},
             "body": '{"title": "401 Unauthorized"}'},
            note="Section 8: KERIA cannot sign a refusal issued before it resolves the agent. "
                 "Reported as an authentication failure whose body is not trusted; checked "
                 "before anything else.")
    respond("unsigned-401-with-an-empty-signature", "unauthenticated", asked,
            {"status": 401, "headers": {"Content-Type": "application/json", "Signature": ""},
             "body": '{"title": "401 Unauthorized"}'},
            note="An empty Signature header is no signature, so this is the same unsigned 401 "
                 "(profile section 8).")
    respond("malformed-keyid-beside-an-expected-keyid", "malformed-key", asked, signed_response(
        "malformed-keyid-beside-an-expected-keyid", asked, keyid=padding_bit_alias(AGENT_AID),
        key=AGENT),
        note="Section 9 order with an expected keyid: the keyid's own well-formedness first, "
             "so this is malformed-key and not unknown-key, though it is not the AID expected.")
    respond("unexpected-keyid-is-not-resolved", "unknown-key", asked, signed_response(
        "unexpected-keyid-is-not-resolved", asked, keyid=EITHER_AID),
        note="A well-formed keyid other than the expected one is unknown-key without asking the "
             "key state. Resolving it first would report unsupported-signer.")
    respond("request-body-contradicts-the-requests-digest", "digest-mismatch",
            {**asked, "body": '{"name": "mallory"}'}, answer,
            note="The response covers \"content-digest\";req, and the request body handed to "
                 "the verifier does not match the request's Content-Digest (profile section 5).")
    respond("unsigned-200", "missing-signature", asked,
            {"status": 200, "headers": {"Content-Type": "application/json"},
             "body": '{"done": true}'},
            note="Every unsigned response other than a 401 is missing-signature.")

    # keri_vectors_format 8, profile 1.2 (@7ve9r2c6): each disagreement the 2026-11-11 review
    # found between the profile text, its vectors, keripy and signify-ts gets the case that pins it.
    add("mixed-order-b-keyid", "malformed-key", signed_request(
        "mixed-order-b-keyid", keyid=qb64("B", MIXED), key=NON_TRANSFERABLE),
        note="A well-formed B keyid whose key is on the curve and not of small order, but of "
             "mixed order: a subgroup point plus a point of order 8. It is not a valid point of "
             "the prime-order subgroup, so it is refused before the signature is examined "
             "(profile R1).")
    respond("weak-b-keyid-beside-an-expected-keyid", "malformed-key", asked, signed_response(
        "weak-b-keyid-beside-an-expected-keyid", asked, keyid=qb64("B", b"\x01" + bytes(31)),
        key=NON_TRANSFERABLE),
        note="A small-order B keyid that is also not the AID expected. The key a B keyid carries "
             "is part of the keyid's own well-formedness, checked before the expected keyid is "
             "compared, so this is malformed-key and not unknown-key (profile section 9).")
    add("resolved-key-of-mixed-order", "malformed-key", signed_request(
        "resolved-key-of-mixed-order", keyid=WEAK_KEY_AID),
        note="A transferable AID whose key state holds a mixed-order key. A resolved key that is "
             "not a valid prime-order point is malformed-key as it is resolved, not "
             "signature-mismatch (profile R1, section 9).")
    add("decimal-created", "malformed-signature-input",
        tamper(post, "Signature-Input", f"created={AT}", f"created={AT}.0"),
        note="created as an RFC 8941 Decimal with a zero fraction. It is not an Integer, and a "
             "verifier must not read it as the whole number it equals (profile section 4).")
    add("decimal-expires", "malformed-signature-input", tamper(
        signed_request("decimal-expires", expires=AT + 100), "Signature-Input",
        f"expires={AT + 100}", f"expires={AT + 100}.0"),
        note="expires as an RFC 8941 Decimal (profile section 4).")
    add("empty-signature-input", "malformed-signature-input", {**get, "headers": {
        **get["headers"], "Signature-Input": " "}},
        note="Signature-Input present and empty once SP and HTAB are trimmed: malformed, not "
             "absent (profile section 4).")
    add("empty-signature-on-a-request", "malformed-signature", {**get, "headers": {
        **get["headers"], "Signature": " "}},
        note="Signature present and empty once SP and HTAB are trimmed, on a request: neither "
             "form of section 8 (profile section 9). An empty Signature on a response is unsigned "
             "instead.")
    add("ed448-keyid-with-no-key-state", "unknown-key", signed_request(
        "ed448-keyid-with-no-key-state", keyid=cesr("1AAD", bytes(range(57))), key=CONTROLLER),
        note="A well-formed transferable Ed448 prefix (code 1AAD) the verifier has no KEL for. "
             "It is an AID under keripy's PreDex codes, so it is unknown-key, not malformed-key "
             "(profile R1).")
    add("non-transferable-secp256k1-keyid", "unsupported-algorithm", signed_request(
        "non-transferable-secp256k1-keyid", keyid=cesr("1AAA", bytes([2]) + bytes(range(32))),
        key=CONTROLLER),
        note="A well-formed non-transferable secp256k1 prefix (code 1AAA). Its key is in the "
             "prefix and is not Ed25519 (profile R1).")
    add("host-keeps-its-default-port", "signature-mismatch", signed_request(
        "host-keeps-its-default-port", url="/identifiers",
        headers={"Host": "keria.example.com:443"}),
        policy={"authorities": ["keria.example.com"]},
        note="A verifier with only Host does not know the scheme, so it uses Host as received "
             "and removes no port: the covered @authority is keria.example.com:443, which this "
             "verifier does not serve (profile section 2).")
    add("host-with-a-no-break-space", "signature-mismatch", {**(lambda m: {**m, "headers": {
        **m["headers"], "Host": "keria.example.com\u00a0"}})(signed_request(
            "host-with-a-no-break-space", url="/identifiers",
            headers={"Host": "keria.example.com"}))},
        policy={"authorities": ["keria.example.com"]},
        note="Only SP and HTAB are trimmed from Host, so a trailing no-break space leaves a value "
             "that is not a valid authority and a base that cannot be built (profile section 2).")
    add("unannounced-body-and-stale", "signature-stale", {**signed_request(
        "unannounced-body-and-stale", body=None), "body": BODY}, now=AT + MAX_AGE + SKEW + 1,
        note="Two defects: a body no header announced arrives without a covered content-digest, "
             "and created is one second past the stale boundary. The body stage runs after "
             "freshness, so a verifier holding the body reports what one reading it later "
             "would: signature-stale (profile section 9).")
    respond("response-body-uncovered-and-status-altered", "insufficient-coverage", asked,
            {**signed_response("response-body-uncovered-and-status-altered", asked, body=None),
             "status": 201, "body": '{"done": true}'},
            note="Two defects: response content without a covered content-digest, and a status "
                 "changed in transit. A response is judged by its content at the covered list, "
                 "before the signature, so this is insufficient-coverage (profile section 9).")

    # Mode (section 8). Carried as data: fiki has no legacy parser, so it cannot tell a legacy
    # header from a malformed one, and it never sends a legacy request.
    why = ("fiki does not implement legacy mode, so it cannot detect a "
           "legacy header or know that a request was legacy. The legacy half is legacy.json's "
           "material verbatim, apart from what the note says.")
    boot = signed_request("mode:canonical-boot", url=f"{HOST}/boot")
    legacy_response = next(entry for entry in LEGACY if entry["id"] == "keria-response-from-agent")
    add("legacy-response-to-a-canonical-request", "mode-mismatch", boot,
        {"status": legacy_response["status"], "headers": dict(legacy_response["headers"]),
         "body": None}, policy={"expected_keyid": legacy_response["keyid"]},
        verified_by_fiki=False, why=why,
        note="A canonical request to /boot answered in legacy mode: legacy.json's "
             "keria-response-from-agent. The legacy response covers neither status nor body, "
             "so a client that sent a canonical request refuses it before any canonical check.")
    legacy_request = next(entry for entry in LEGACY if entry["id"] == "keria-request-to-boot")
    legacy_sent = {"method": legacy_request["method"], "url": f"{HOST}{legacy_request['path']}",
                   "headers": {name: value for name, value in legacy_request["headers"].items()
                               if name != "Content-Length"},
                   "body": None}
    add("canonical-response-to-a-legacy-request", "mode-mismatch", legacy_sent,
        signed_response("mode:canonical-answer", legacy_sent), policy=agent,
        verified_by_fiki=False, why=why,
        note="legacy.json's keria-request-to-boot, without its Content-Length (which the legacy "
             "signature does not cover, so the request still verifies in legacy mode), "
             "answered by a canonical response. A client answers in the mode it asked in, and "
             "refuses the other (section 8).")

    # The signer-side refusal.
    cases.append({
        "id": "sign-body-without-digest",
        "kind": "sign-request",
        "note": "A signer asked to sign a non-empty body without covering content-digest "
                "refuses. The only signer-side code.",
        "request": {"method": "POST", "url": f"{HOST}/identifiers", "headers": {},
                    "body": BODY},
        "covered": ['"@method"', '"@path"', '"@query"'],
        "keyid": CONTROLLER_AID,
        "seed_hex": CONTROLLER.seed.hex(),
        "error": "uncovered-body",
    })
    cases.append({
        "id": "sign-below-the-minimum",
        "kind": "sign-request",
        "note": "A signer asked to cover less than the request minimum set refuses (profile "
                "section 3).",
        "request": {"method": "GET", "url": f"{HOST}/identifiers?type=rot", "headers": {},
                    "body": None},
        "covered": ['"@method"', '"@path"'],
        "keyid": CONTROLLER_AID,
        "seed_hex": CONTROLLER.seed.hex(),
        "error": "insufficient-coverage",
    })
    for case in cases[-2:]:
        request = case["request"]
        try:
            sign_request(key=CONTROLLER, method=request["method"], url=request["url"],
                         headers=request["headers"], body=body_bytes(request["body"]),
                         covered=case["covered"], keyid=CONTROLLER_AID, minimum=REQUEST_MINIMUM)
        except FikiError as ex:
            if CODES[type(ex).__name__] != case["error"]:
                raise SystemExit(f"{case['id']}: fiki reports {type(ex).__name__}")
        else:
            raise SystemExit(f"{case['id']}: fiki signed it")

    return {**policy_header("Messages a canonical verifier must REFUSE, and the section 9 code."),
            "codes": PROFILE_CODES, "cases": cases}


# --- legacy material, static, with provenance ---

KERIA = {"repo": "WebOfTrust/keria", "commit": "7e685edaaeca408919f9adf6789a6626d9c5cf79",
         "file": "tests/core/test_authing.py"}
SIGNIFY = {"repo": "WebOfTrust/signify-ts", "commit": "ffba8406ef5d0c148decefd6ecfb2f31c480a0ef",
           "file": "test/core/authing.test.ts"}


def legacy_base(fields, params):
    """The legacy base as keripy's ending.siginput builds it, written out rather than built."""
    lines = [f'"{name}": {value}' for name, value in fields]
    lines.append(f'"@signature-params: {params}"')
    return "\n".join(lines)


LEGACY = [
    {
        "id": "keria-request-to-boot",
        "kind": "request",
        "source": {**KERIA, "lines": "36-164",
                   "test": "test_signed_header_authenticator, the 'Good signature' request"},
        "method": "POST",
        "path": "/boot",
        "headers": {
            "Content-Type": "application/json",
            "Content-Length": "256",
            "Connection": "close",
            "Signify-Resource": "EPwUOBk9QkxPM20JBaf_pFXPytSjTUoyxbx95uZJE1Hq",
            "Signify-Timestamp": "2022-09-24T00:05:48.196795+00:00",
            "Signature-Input": 'signify=("signify-resource" "@method" "@path" '
                               '"signify-timestamp");created=1609459200;'
                               'keyid="EPwUOBk9QkxPM20JBaf_pFXPytSjTUoyxbx95uZJE1Hq";'
                               'alg="ed25519"',
            "Signature": 'indexed="?0";signify="0BDBVr5ape8f9nV60ThhWOKvu5HKXQc5798Sz95FIoqXQ9vvL8'
                         'HoYsLRp5aN86MIXr0GqH37SowsmTP-k9UhYSkN"',
        },
        "keyid": "EPwUOBk9QkxPM20JBaf_pFXPytSjTUoyxbx95uZJE1Hq",
        "key": "DAFFYufJkgED00EwDPDUfQ2jYT_kOkGKYRGYxySX_VjW",
        "created": 1609459200,
        "mocked_now": "2021-01-01T00:00:00+00:00 (keria tests/conftest.py mockHelpingNowUTC)",
        "fields": [["signify-resource", "EPwUOBk9QkxPM20JBaf_pFXPytSjTUoyxbx95uZJE1Hq"],
                   ["@method", "POST"], ["@path", "/boot"],
                   ["signify-timestamp", "2022-09-24T00:05:48.196795+00:00"]],
        "params": "(signify-resource @method @path signify-timestamp);created=1609459200;"
                  "keyid=EPwUOBk9QkxPM20JBaf_pFXPytSjTUoyxbx95uZJE1Hq;alg=ed25519",
        "note": "The controller of salt b'1111456789abcdef'. key is its current signing key "
                "(the Verfer), which the test does not print: it was derived by running keripy "
                "2.0.0-dev6 from the same salt and confirmed by the signature verifying below.",
    },
    {
        "id": "keria-response-from-agent",
        "kind": "response",
        "source": {**KERIA, "lines": "166-185",
                   "test": "test_signed_header_authenticator, authn.outbound"},
        "method": "POST",
        "path": "/boot",
        "status": 200,
        "headers": {
            "connection": "close",
            "content-length": "256",
            "content-type": "application/json",
            "signify-resource": "EEAJjjsbswsipSk6qypNw9bKszVfkAWvAYonKTKWHnDt",
            "signify-timestamp": "2021-01-01T00:00:00.000000+00:00",
            "Signature-Input": 'signify=("signify-resource" "@method" "@path" '
                               '"signify-timestamp");created=1609459200;'
                               'keyid="EEAJjjsbswsipSk6qypNw9bKszVfkAWvAYonKTKWHnDt";'
                               'alg="ed25519"',
            "Signature": 'indexed="?0";signify="0BBWiqPdnUjfwkDcFQQyUUjjATXp0mRgG7S9ikr_XZkp0Nbv77'
                         'dY8syrdpJTLuU4gTfmMYJb4OIR5oN7K02CV_0I"',
        },
        "keyid": "EEAJjjsbswsipSk6qypNw9bKszVfkAWvAYonKTKWHnDt",
        "key": "DKDhlTWVfELdh0IbjoZ-ox0PI3xxGyrKUvg31KPTedcG",
        "created": 1609459200,
        "mocked_now": "2021-01-01T00:00:00+00:00 (keria tests/conftest.py mockHelpingNowUTC)",
        "fields": [["signify-resource", "EEAJjjsbswsipSk6qypNw9bKszVfkAWvAYonKTKWHnDt"],
                   ["@method", "POST"], ["@path", "/boot"],
                   ["signify-timestamp", "2021-01-01T00:00:00.000000+00:00"]],
        "params": "(signify-resource @method @path signify-timestamp);created=1609459200;"
                  "keyid=EEAJjjsbswsipSk6qypNw9bKszVfkAWvAYonKTKWHnDt;alg=ed25519",
        "note": "KERIA's agent signing its response to the request above: the legacy response "
                "base is the REQUEST's method and path plus the response's own headers, and "
                "covers neither status nor body. key is the agent's current key, derived by "
                "running keripy 2.0.0-dev6 with the test's salt and caid and confirmed by the "
                "signature verifying below.",
    },
    {
        "id": "signify-ts-response-verified",
        "kind": "response",
        "source": {**SIGNIFY, "lines": "30-170",
                   "test": "SignedHeaderAuthenticator.verify, 'verify signature on Response', "
                           "the 'Good' case"},
        "method": "GET",
        "path": "/identifiers/aid1",
        "status": 200,
        "headers": {
            "Content-Length": "898",
            "Content-Type": "application/json",
            "Signify-Timestamp": "2023-05-22T00:37:00.248708+00:00",
            "Signify-Resource": "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei",
            "Signature-Input": 'signify=("signify-resource" "@method" "@path" '
                               '"signify-timestamp");created=1684715820;'
                               'keyid="EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei";'
                               'alg="ed25519"',
            "Signature": 'indexed="?0";signify="0BDLh8QCytVBx1YMam4Vt8s4b9HAW1dwfE4yU5H_w1V6gUvPBo'
                         'VGWQlIMdC16T3WFWHDHCbMcuceQzrr6n9OULsK"',
        },
        "keyid": "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei",
        "key": "DMZh_y-H5C3cSbZZST-fqnsmdNTReZxIh0t2xSTOJQ8a",
        "created": 1684715820,
        "mocked_now": "none: legacy verification checks no freshness",
        "fields": [["signify-resource", "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei"],
                   ["@method", "GET"], ["@path", "/identifiers/aid1"],
                   ["signify-timestamp", "2023-05-22T00:37:00.248708+00:00"]],
        "params": "(signify-resource @method @path signify-timestamp);created=1684715820;"
                  "keyid=EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei;alg=ed25519",
        "note": "The request was GET http://127.0.0.1:3901/identifiers/aid1. key is the agent "
                "Verfer the test constructs (aaid).",
    },
    {
        "id": "signify-ts-request-prepared",
        "kind": "request",
        "source": {**SIGNIFY, "lines": "172-222",
                   "test": "SignedHeaderAuthenticator.prepare, 'Create signed headers for a "
                           "request'"},
        "method": "POST",
        "path": "/boot",
        "url": "http://127.0.0.1:3903/boot",
        "headers": {
            "Content-Type": "application/json",
            "Content-Length": "256",
            "Connection": "close",
            "Signify-Resource": "EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs",
            "Signify-Timestamp": "2022-09-24T00:05:48.196795+00:00",
            "Signature-Input": 'signify=("@method" "@path" "signify-resource" '
                               '"signify-timestamp");created=1609459200;'
                               'keyid="DN54yRad_BTqgZYUSi_NthRBQrxSnqQdJXWI5UHcGOQt";'
                               'alg="ed25519"',
            "Signature": 'indexed="?0";signify="0BChvN_BWAf-mgEuTnWfNnktgHdWOuOh9cWc4o0GFWuZOwra3D'
                         'yJT5dJ_6BX7AANDOTnIlAKh5Sg_9qGQXHjj5oJ"',
        },
        "keyid": "DN54yRad_BTqgZYUSi_NthRBQrxSnqQdJXWI5UHcGOQt",
        "key": "DN54yRad_BTqgZYUSi_NthRBQrxSnqQdJXWI5UHcGOQt",
        "created": 1609459200,
        "mocked_now": "2021-01-01T00:00:00.000000+00:00 (utilApi.nowUTC spied)",
        "fields": [["@method", "POST"], ["@path", "/boot"],
                   ["signify-resource", "EWJkQCFvKuyxZi582yJPb0wcwuW3VXmFNuvbQuBpgmIs"],
                   ["signify-timestamp", "2022-09-24T00:05:48.196795+00:00"]],
        "params": "(@method @path signify-resource signify-timestamp);created=1609459200;"
                  "keyid=DN54yRad_BTqgZYUSi_NthRBQrxSnqQdJXWI5UHcGOQt;alg=ed25519",
        "note": "Signed by salter.signer() of salt '0123456789abcdef'. Here keyid is the "
                "signer's own Verfer (a D code), not an AID, because the test signs with a "
                "bare signer; the legacy verifier resolves Signify-Resource instead.",
    },
]


# Legacy messages from controllers with more than one current key, generated (format 7, profile
# version 1.1 section 8, @2wdtp6md; format 8, version 1.2, @7ve9r2c6). KERIA's and signify-ts's
# tests pin none, because every controller they sign for has one key, which is exactly why
# version 1's first-key rule went unnoticed, and why version 1.1's single-signer rule broke
# signify-ts's createSignedRequest from a two-key AID unnoticed too.

LEGACY_TIMESTAMP = "2023-11-14T22:13:20.000000+00:00"
ZERO_FIRST = [seeded(11), seeded(12)]
EITHER = [seeded(14), seeded(15)]
B_RESOURCE = seeded(16)


def sufficient_keys(keys: list[str], threshold) -> list[str]:
    """Profile section 8 at version 1.2: every current key that satisfies the threshold alone.

    The same forms effective_signer reads; anything else aborts.
    """
    if isinstance(threshold, str):
        return list(keys) if int(threshold, 16) == 1 else []
    if len(threshold) == len(keys) and all(isinstance(w, str) for w in threshold):
        return [key for key, weight in zip(keys, threshold) if Fraction(weight) >= 1]
    raise SystemExit(f"a threshold the vectors do not use: {threshold!r}")


def legacy_signed(case_id, *, aid, keys, threshold, signer, note, input_header=None,
                  error=None):
    """A legacy GET as Signify's SignedHeaderAuthenticator.sign builds it, signed by signer.

    keys None means the verifier holds no key state for aid. input_header replaces the
    Signature-Input header after signing, for a case refused before any key is tried, and error
    is then the code it must get; otherwise the error follows from the key state and the signer.
    """
    fields = [["signify-resource", aid], ["@method", "GET"], ["@path", "/identifiers"],
              ["signify-timestamp", LEGACY_TIMESTAMP]]
    params = (f"(signify-resource @method @path signify-timestamp);created={AT};"
              f"keyid={aid};alg=ed25519")
    raw = signer.sign(legacy_base(fields, params).encode("utf-8"))
    cesr_signature = "0B" + base64.urlsafe_b64encode(b"\x00\x00" + raw).decode("ascii")[2:]
    state = None if keys is None else {"keys": [verfer(key) for key in keys],
                                       "threshold": threshold}
    sufficient = None if keys is None else sufficient_keys(state["keys"], threshold)
    if keys is None:
        derived = "unknown-key"
    elif not sufficient:
        derived = "unsupported-signer"
    elif verfer(signer) in sufficient:
        derived = None
    else:
        derived = "signature-mismatch"
    if input_header is None:
        error = derived
    elif derived is not None or error is None:
        raise SystemExit(f"{case_id}: a header refusal needs a key state that would accept")
    entry = {
        "id": case_id,
        "kind": "request",
        "source": {"repo": "bakobo/fiki", "file": "vectors/keri/generate.py",
                   "generated": "Signed by fiki-py with the seed in seed_hex; no deployed "
                                "test pins a legacy message from a multi-key controller."},
        "method": "GET",
        "path": "/identifiers",
        "headers": {
            "Signify-Resource": aid,
            "Signify-Timestamp": LEGACY_TIMESTAMP,
            "Signature-Input": input_header or ('signify=("signify-resource" "@method" "@path" '
                                                f'"signify-timestamp");created={AT};'
                                                f'keyid="{aid}";alg="ed25519"'),
            "Signature": f'indexed="?0";signify="{cesr_signature}"',
        },
        "keyid": aid,
        "key": verfer(signer),
        "seed_hex": signer.seed.hex(),
        "created": AT,
        "mocked_now": "none: legacy verification checks no freshness",
        "key_state": state,
        "sufficient_keys": None if sufficient is None else [b64url(raw_of(key))
                                                             for key in sufficient],
        "fields": fields,
        "params": params,
        "note": note,
    }
    if error is not None:
        entry["error"] = error
    return entry


LEGACY_MULTIKEY = [
    legacy_signed(
        "legacy-either-of-two-keys-signed-by-the-first", aid=synthetic_aid("legacy: either key"),
        keys=EITHER, threshold="1", signer=EITHER[0],
        note="Threshold 1 over two keys, signed by the first, as signify-ts's createSignedRequest "
             "signs for an AID made with two keys. Either key alone satisfies the threshold, so "
             "the verifier tries both and this verifies (profile section 8). Version 1.1 refused "
             "it as unsupported-signer."),
    legacy_signed(
        "legacy-either-of-two-keys-signed-by-the-second",
        aid=synthetic_aid("legacy: either key"), keys=EITHER, threshold="1", signer=EITHER[1],
        note="The same controller signed by its second key, which also satisfies the threshold "
             "alone: accepted (profile section 8)."),
    legacy_signed(
        "legacy-two-of-three-group", aid=synthetic_aid("legacy: two of three keys"),
        keys=GROUP, threshold="2", signer=GROUP[0],
        note="A 2-of-3 group signed by its first key alone. No one key satisfies the threshold, "
             "so there is no key to try (profile section 8). Version 1 took the first current "
             "key and accepted this, letting one member act as the group."),
    legacy_signed(
        "legacy-passcode-rotated-controller", aid=synthetic_aid("legacy: passcode rotated"),
        keys=[PASSCODE_NEW, PRIOR_NEXT], threshold=["1", "0"], signer=PASSCODE_NEW,
        note="A Signify controller after its passcode is rotated: keys [new, prior-next], "
             "threshold ['1','0']. Its first key is the only one that satisfies the threshold "
             "alone, so its legacy traffic verifies as it always has."),
    legacy_signed(
        "legacy-weight-zero-first-key-signs", aid=synthetic_aid("legacy: weight-zero first key"),
        keys=ZERO_FIRST, threshold=["0", "1"], signer=ZERO_FIRST[0],
        note="Threshold ['0','1'], signed by the first key, which carries no weight: the only key "
             "that satisfies the threshold alone is the second, and the signature does not "
             "verify under it. Version 1 took the first key and accepted this, so a compromised "
             "key rotated to weight 0 kept authenticating."),
    legacy_signed(
        "legacy-weight-zero-first-key-effective-second",
        aid=synthetic_aid("legacy: weight-zero first key"),
        keys=ZERO_FIRST, threshold=["0", "1"], signer=ZERO_FIRST[1],
        note="The same controller signed by its second key, which satisfies the threshold alone: "
             "accepted. Version 1 refused it, since it checked the first key."),
    legacy_signed(
        "legacy-non-transferable-resource-without-key-state", aid=B_RESOURCE.aid, keys=None,
        threshold=None, signer=B_RESOURCE,
        note="Signify-Resource is a B prefix the verifier holds no key state for (key_state "
             "null). Legacy mode never takes a key from a prefix, so this is unknown-key though "
             "the prefix's key made the signature (profile section 8)."),
    legacy_signed(
        "legacy-signature-input-covering-an-integer",
        aid=synthetic_aid("legacy: an integer in the covered list"), keys=[CONTROLLER],
        threshold="1", signer=CONTROLLER,
        input_header=('signify=("signify-resource" "@method" "@path" 1);created='
                      f'{AT};keyid="{synthetic_aid("legacy: an integer in the covered list")}";'
                      'alg="ed25519"'),
        error="malformed-signature-input",
        note="The Signature-Input's covered list holds an Integer where a String belongs, "
             "replaced after signing; base and the signature are the message before that. Its "
             "key state would accept it. A verifier refuses it with a section 9 code, never "
             "with a parser's own exception (profile section 9)."),
]


def legacy():
    cases = []
    for entry in LEGACY + LEGACY_MULTIKEY:
        entry = dict(entry)
        fields, params = entry.pop("fields"), entry.pop("params")
        entry["base"] = legacy_base(fields, params)
        signature = entry["headers"]["Signature"].split('signify="', 1)[1].rstrip('"')
        raw_signature = base64.urlsafe_b64decode("AA" + signature[2:])[2:]
        Ed25519PublicKey.from_public_bytes(raw_of(entry["key"])).verify(
            raw_signature, entry["base"].encode())
        if entry.get("error") == "signature-mismatch":
            for key in entry["sufficient_keys"]:
                try:
                    Ed25519PublicKey.from_public_bytes(
                        base64.urlsafe_b64decode(key + "=")
                    ).verify(raw_signature, entry["base"].encode())
                except InvalidSignature:
                    continue
                raise SystemExit(f"{entry['id']}: verifies under a sufficient key")
        cases.append(entry)
    return {
        **header("Legacy-mode messages pinned in KERIA's and signify-ts's current tests, so each "
                 "implementation proves it still accepts today's traffic (profile section 10). "
                 "fiki does not verify legacy mode; these are static data."),
        "rules": "key is the Ed25519 verification key that made the signature, in CESR qb64 (a "
                 "one-character D code over 32 bytes). base is the legacy signature base keripy's "
                 "ending.siginput builds: field lines, then a final line with the quote placed "
                 "before @signature-params and unquoted identifiers and parameters. The "
                 "signature is the Signature header's signify member, CESR 0B (Ed25519) over "
                 "that base. A legacy verifier checks no freshness. A case pinned from KERIA or "
                 "signify-ts is accepted, and its key is the key the verifier resolves for "
                 "Signify-Resource. A case generated by fiki carries key_state, the key state "
                 "the verifier holds for Signify-Resource (the current signing keys as qb64 "
                 "verfers and the signing threshold in keripy's form), or null when it holds "
                 "none, and sufficient_keys, every current key that satisfies the threshold "
                 "alone, as raw keys in base64url in key-state order (profile section 8). The "
                 "verifier accepts a signature that verifies under any of sufficient_keys. Such a "
                 "case is accepted when it has no error; otherwise error is its section 9 code: "
                 "unknown-key when key_state is null, unsupported-signer when sufficient_keys is "
                 "empty, signature-mismatch when the signature was made by a key not in "
                 "sufficient_keys, and any other code for a header refused before a key is tried, "
                 "whose key state would otherwise accept it.",
        "cases": cases,
    }


def main() -> None:
    out = Path(__file__).resolve().parent
    for name, data in [
        ("rfc9421.json", rfc9421()),
        ("requests.json", requests()),
        ("responses.json", responses()),
        ("refusals.json", refusals()),
        ("legacy.json", legacy()),
    ]:
        (out / name).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                                encoding="utf-8")
        print(f"wrote keri/{name}: {len(data['cases'])} cases")


if __name__ == "__main__":
    main()

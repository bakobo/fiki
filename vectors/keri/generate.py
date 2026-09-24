#!/usr/bin/env python3
"""Regenerate the KERI profile's vector set (``this.i`` @8vwrexxc).

Run from the repository root: ``python3 vectors/keri/generate.py``.

The contract is the KERI profile of RFC 9421 HTTP Message Signatures, version 1 of 2026-09-24,
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
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "py" / "src"))

import http_sfv  # noqa: E402
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
from fiki.errors import FikiError, MalformedKey, UnsupportedSigner  # noqa: E402
from fiki.messages import content_digest  # noqa: E402

# The contract's own format number, separate from vectors_format (@8vwrexxc, @4fhrre0m).
KERI_VECTORS_FORMAT = 2

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

# Section 9's codes in the order it lists them. unauthenticated is listed where section 9 puts
# it, and runs before any other check on a response. mode-mismatch cases are carried as data:
# fiki has no legacy parser, so it cannot tell a legacy header from a malformed one.
PROFILE_CODES = [
    "missing-signature", "missing-signature-input", "malformed-signature",
    "malformed-signature-input", "malformed-signature-label", "missing-signature-label",
    "malformed-signature-value", "mode-mismatch", "duplicate-component", "unsupported-component",
    "insufficient-coverage", "malformed-key", "unknown-key", "unsupported-signer",
    "unsupported-algorithm", "missing-component", "signature-mismatch", "signature-stale",
    "signature-expired", "unauthenticated", "malformed-digest", "digest-mismatch",
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
    "version": 1,
    "date": "2026-09-24",
    "where": "https://github.com/bakobo/fiki/blob/main/docs/keri-profile.md",
    "rules": "Canonical mode only. Refusals are named by the profile's section 9 codes. A "
             "verifier runs its checks in section 9's order and reports the first that fails. "
             "Every refusal case carries exactly one defect, so it has exactly one correct code.",
}

POLICY = {
    "max_age": MAX_AGE,
    "skew": SKEW,
    "request_minimum": [str(component(spec)) for spec in REQUEST_MINIMUM],
    "response_minimum": [str(component(spec)) for spec in RESPONSE_MINIMUM],
    "body_rule": "Profile section 3. A REQUEST has a body when it carries Content-Length above "
                 "zero, any Transfer-Encoding, or a Content-Length that is not a plain decimal, "
                 "or when a non-empty body arrives whatever the headers said. A RESPONSE has a "
                 "body when it has content; its Content-Length is not evidence, since a HEAD or "
                 "304 response announces a length it does not send. A body obliges a covered "
                 "content-digest. A response to a request whose content was non-empty must also "
                 "cover \"content-digest\";req; the request's headers do not count there, "
                 "since both sides hold the whole request by the time a response is signed or "
                 "verified.",
    "freshness": "Profile section 6: refuse created < now - max_age - skew or created > now + "
                 "skew as signature-stale, then expires < now - skew as signature-expired. Each "
                 "case gives the now it assumes, in seconds since the epoch.",
    "case_policy": "A case may carry a policy object whose fields extend this one: "
                   "expected_keyid, the AID a client expects a response from (profile R1); "
                   "authorities, the @authority values a verifier serves (profile section 3).",
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
    "A keyid is a well-formed AID when it is 44 characters, its first character is B, D or E, "
    "and the other 43 are base64url that decode, behind one leading pad character, to 32 "
    "bytes with a zero pad byte, so that re-encoding gives back the keyid exactly. A keyid "
    "that is not is malformed-key. A well-formed B keyid yields its key from the "
    "prefix. Every other well-formed keyid resolves through the key state the verifier holds, "
    "which this table stands in for: absent from the table is unknown-key, and an entry whose "
    "effective_key is null is unsupported-signer. key_state is the state an implementation with "
    "a KERI stack reduces itself (profile R4): the current signing keys as qb64 verfers, and the "
    "signing threshold in keripy's form. The effective key is the one key that satisfies the "
    "threshold alone, when exactly one does."
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

B_AID = NON_TRANSFERABLE.aid
CONTROLLER_AID = synthetic_aid("controller")
AGENT_AID = synthetic_aid("agent")
D_AID = qb64("D", raw_key(INCEPTION))
UNKNOWN_AID = synthetic_aid("a controller this verifier holds no KEL for")
PASSCODE_AID = synthetic_aid("a Signify controller after a passcode rotation")
EITHER_AID = synthetic_aid("either of two keys suffices")
TWO_OF_THREE_AID = synthetic_aid("two of three keys")

SIGNERS = {B_AID: NON_TRANSFERABLE, CONTROLLER_AID: CONTROLLER, AGENT_AID: AGENT, D_AID: ROTATED,
           PASSCODE_AID: PASSCODE_NEW, EITHER_AID: GROUP[0], TWO_OF_THREE_AID: GROUP[0]}


def verfer(key: Key) -> str:
    return qb64("D", raw_key(key))


def transferable(keyid, keys, threshold, effective, note, **extra):
    return {"keyid": keyid, "kind": "transferable",
            "effective_key": None if effective is None else b64url(raw_key(effective)),
            "seed_hex": SIGNERS[keyid].seed.hex(),
            "key_state": {"keys": [verfer(key) for key in keys], "threshold": threshold},
            **extra, "note": note}


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
]


def well_formed_aid(keyid: str) -> bool:
    """KEYS_RULE's test, shared by this generator and fiki-py's driver."""
    if len(keyid) != 44 or keyid[0] not in "BDE":
        return False
    try:
        decoded = base64.b64decode("A" + keyid[1:], altchars=b"-_", validate=True)
    except ValueError:
        return False
    # Canonical only: a non-zero bit in the pad byte the code replaced is a second spelling of
    # the same 32 bytes, and a B keyid spelled that way would alias the same key.
    return len(decoded) == 33 and qb64(keyid[0], decoded[1:]) == keyid


def resolver(keys: list[dict]):
    """What a KERI verifier's key lookup does, for a keys table: authoritative, never a decode."""
    table = {entry["keyid"]: entry for entry in keys if entry["kind"] == "transferable"}

    def resolve(keyid: str):
        if not well_formed_aid(keyid):
            raise MalformedKey(f'"{keyid}" is not a well-formed AID.', keyid=keyid)
        if keyid.startswith("B"):
            return verifying_key(keyid).public_bytes_raw()
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
                   minimum=REQUEST_MINIMUM):
    """A request signed as a Signify client would sign it: refusing, as the profile's signer
    does, to cover less than the minimum set unless a case deliberately asks for that."""
    key = key or SIGNERS[keyid]
    sending = dict(headers or {})
    if emit_alg:
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
    common = dict(max_age=policy["max_age"], skew=policy["skew"], now=now,
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
    Ed25519PublicKey.from_public_bytes(resolver(keys)(params["keyid"])).verify(
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
        accept("authority-in-the-served-set", signed_request(
            "authority-in-the-served-set", url="/identifiers",
            headers={"Host": "keria.example.com"}),
            policy={"authorities": ["keria.example.com"]},
            note="A covered @authority the verifier serves, rebuilt from Host."),
    ]
    return {**policy_header("Signed requests a canonical verifier must ACCEPT, with the base."),
            "verify_only": ["digest-with-an-unknown-algorithm-member",
                            "digest-with-two-recognized-members"],
            "verify_only_why": "These cases carry a Content-Digest with a member a sha-256-only "
                               "signer does not emit, so such a signer cannot reproduce their "
                               "headers byte for byte. Verify them; do not expect to sign them.",
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
    add("body-arrived-without-digest", "insufficient-coverage", {**signed_request(
        "body-arrived-without-digest", body=None), "body": BODY},
        note="No header announced a body, and one arrived: the read-time rule of section 3.")

    # The key.
    add("keyid-not-an-aid", "malformed-key", signed_request(
        "keyid-not-an-aid", keyid="not-an-aid", key=CONTROLLER),
        note="The keyid is not a well-formed AID.")
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
        "digest-with-no-recognized-algorithm", headers={"Content-Digest": "x-unknown=:AAAA:"}),
        note="No sha-256 or sha-512 member: an error, not a pass.")
    add("swapped-body", "digest-mismatch", {**post, "body": '{"name": "mallory"}'},
        note="The body does not match its covered digest.")
    add("two-recognized-digests-one-mismatching", "digest-mismatch", signed_request(
        "two-recognized-digests-one-mismatching",
        headers={"Content-Digest": content_digest(BODY.encode()) + ", sha-512=:"
                 + base64.b64encode(hashlib.sha512(b"other").digest()).decode() + ":"}),
        note="sha-256 matches and sha-512 does not; every recognized member must match.")

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
    respond("unsigned-401", "unauthenticated", asked,
            {"status": 401, "headers": {"Content-Type": "application/json"},
             "body": '{"title": "401 Unauthorized"}'},
            note="Section 8: KERIA cannot sign a refusal issued before it resolves the agent. "
                 "Reported as an authentication failure whose body is not trusted; checked "
                 "before anything else.")
    respond("unsigned-200", "missing-signature", asked,
            {"status": 200, "headers": {"Content-Type": "application/json"},
             "body": '{"done": true}'},
            note="Every unsigned response other than a 401 is missing-signature.")

    # Mode (section 8). Carried as data: fiki has no legacy parser, so it cannot tell a legacy
    # header from a malformed one, and it never sends a legacy request.
    why = ("fiki does not implement legacy mode (this.i @07wstqk7), so it cannot detect a "
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
                "section 3, draft 6).",
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


def legacy():
    cases = []
    for entry in LEGACY:
        entry = dict(entry)
        fields, params = entry.pop("fields"), entry.pop("params")
        entry["base"] = legacy_base(fields, params)
        signature = entry["headers"]["Signature"].split('signify="', 1)[1].rstrip('"')
        Ed25519PublicKey.from_public_bytes(
            base64.urlsafe_b64decode("A" + entry["key"][1:])[1:]
        ).verify(base64.urlsafe_b64decode("AA" + signature[2:])[2:], entry["base"].encode())
        cases.append(entry)
    return {
        **header("Legacy-mode messages pinned in KERIA's and signify-ts's current tests, so each "
                 "implementation proves it still accepts today's traffic (profile section 10). "
                 "fiki does not verify legacy mode; these are static data."),
        "rules": "key is the signer's current Ed25519 verification key in CESR qb64 (a one-"
                 "character D code over 32 bytes). base is the legacy signature base keripy's "
                 "ending.siginput builds: field lines, then a final line with the quote placed "
                 "before @signature-params and unquoted identifiers and parameters. The "
                 "signature is the Signature header's signify member, CESR 0B (Ed25519) over "
                 "that base. A legacy verifier checks no freshness.",
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

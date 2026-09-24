#!/usr/bin/env python3
"""Regenerate the KERI profile's vector set (``this.i`` @8vwrexxc).

Run from the repository root: ``python3 vectors/keri/generate.py``.

The contract is the KERI profile of RFC 9421 HTTP Message Signatures, draft 4 of 2026-09-24,
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
from fiki.errors import FikiError, MalformedKey  # noqa: E402
from fiki.messages import content_digest  # noqa: E402

# The contract's own format number, separate from vectors_format (@8vwrexxc, @4fhrre0m).
KERI_VECTORS_FORMAT = 1

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

# Section 9 in its own order. mode-mismatch and unsupported-signer are listed and never produced
# here: fiki has no legacy mode and its resolver yields one key.
PROFILE_CODES = [
    "missing-signature", "missing-signature-input", "malformed-signature",
    "malformed-signature-input", "malformed-signature-label", "missing-signature-label",
    "malformed-signature-value", "mode-mismatch", "duplicate-component", "unsupported-component",
    "insufficient-coverage", "malformed-key", "unknown-key", "unsupported-signer",
    "unsupported-algorithm", "missing-component", "signature-mismatch", "signature-stale",
    "signature-expired", "malformed-digest", "digest-mismatch", "uncovered-body",
]

MAX_AGE = 300
SKEW = 60
AT = 1700000000
LABEL = "signify"
HOST = "https://keria.example.com"
BODY = '{"name": "alice", "salt": "0ACDEyMzQ1Njc4OWFiY2RlZg"}'

PROFILE = {
    "title": "KERI profile of RFC 9421 HTTP Message Signatures",
    "draft": 4,
    "date": "2026-09-24",
    "where": "bakobo/keripy, .ignored/rfc9421/profile.md (not yet published)",
    "rules": "Canonical mode only. Refusals are named by the profile's section 9 codes. A "
             "verifier runs its checks in section 9's order and reports the first that fails; "
             "every refusal case has exactly one defect, so it has exactly one correct code.",
}

POLICY = {
    "max_age": MAX_AGE,
    "skew": SKEW,
    "request_minimum": [str(component(spec)) for spec in REQUEST_MINIMUM],
    "response_minimum": [str(component(spec)) for spec in RESPONSE_MINIMUM],
    "body_rule": "Profile section 3. A message has a body when it carries Content-Length above "
                 "zero or any Transfer-Encoding, or when a non-empty body arrives whatever the "
                 "headers said; a body obliges a covered content-digest. A response to a request "
                 "that had a body must also cover \"content-digest\";req.",
    "freshness": "Profile section 6: refuse created < now - max_age - skew or created > now + "
                 "skew as signature-stale, then expires < now - skew as signature-expired. Each "
                 "case gives the now it assumes, in seconds since the epoch.",
}

ENCODING = {
    "body": "The content as a UTF-8 string, after any transfer coding is removed; null means no "
            "body is handed to the verifier.",
    "headers": "Field names as a sender would write them; a verifier matches them "
               "case-insensitively. Each value is one field line.",
    "covered": "Component identifiers in their RFC 8941 serialized form, as they appear in "
               "Signature-Input: \"@method\", \"@path\";req.",
    "public_key": "The raw 32-byte Ed25519 public key, base64url without padding.",
    "signature": "The raw 64-byte Ed25519 signature, standard base64, as inside the Signature "
                 "header's colons.",
    "seed_hex": "The 32-byte Ed25519 seed, hex, so a signer can reproduce every signature; "
                "Ed25519 is deterministic.",
}


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


NON_TRANSFERABLE = Key.from_seed(bytes(range(32)))
CONTROLLER = Key.from_seed(bytes(range(2, 34)))
AGENT = Key.from_seed(bytes(range(3, 35)))
INCEPTION = Key.from_seed(bytes(range(4, 36)))
ROTATED = Key.from_seed(bytes(range(5, 37)))

B_AID = NON_TRANSFERABLE.aid
CONTROLLER_AID = synthetic_aid("controller")
AGENT_AID = synthetic_aid("agent")
D_AID = qb64("D", raw_key(INCEPTION))
UNKNOWN_AID = synthetic_aid("a controller this verifier holds no KEL for")

SIGNERS = {B_AID: NON_TRANSFERABLE, CONTROLLER_AID: CONTROLLER, AGENT_AID: AGENT, D_AID: ROTATED}

KEYS = [
    {"keyid": B_AID, "kind": "non-transferable", "public_key": b64url(raw_key(NON_TRANSFERABLE)),
     "seed_hex": NON_TRANSFERABLE.seed.hex(),
     "note": "Ed25519N. The verifier derives the key from the prefix itself and holds no KEL."},
    {"keyid": CONTROLLER_AID, "kind": "transferable", "public_key": b64url(raw_key(CONTROLLER)),
     "seed_hex": CONTROLLER.seed.hex(),
     "note": "A controller's current signing key, as the KEL the verifier holds says. The AID "
             "is synthetic: a well-formed E code, not the digest of a real inception event."},
    {"keyid": AGENT_AID, "kind": "transferable", "public_key": b64url(raw_key(AGENT)),
     "seed_hex": AGENT.seed.hex(),
     "note": "An agent's current signing key; it signs the responses. Synthetic like the "
             "controller's."},
    {"keyid": D_AID, "kind": "transferable", "public_key": b64url(raw_key(ROTATED)),
     "seed_hex": ROTATED.seed.hex(), "embedded_key": b64url(raw_key(INCEPTION)),
     "embedded_seed_hex": INCEPTION.seed.hex(),
     "note": "A basic transferable prefix after one rotation. Decoding the prefix yields "
             "embedded_key, the INCEPTION key; the current key is public_key and comes only "
             "from the KEL (profile R1). A verifier that decodes a D keyid as a key accepts a "
             "rotated-away key."},
]


def header(about: str) -> dict:
    return {
        "about": about,
        "keri_vectors_format": KERI_VECTORS_FORMAT,
        "generated_by": "vectors/keri/generate.py",
        "profile": PROFILE,
        "encoding": ENCODING,
    }


def policy_header(about: str) -> dict:
    return {**header(about), "policy": POLICY, "keys": KEYS}


def resolve(keyid: str):
    """What a KERI verifier's key lookup does, for the keys above: authoritative, never a decode."""
    for entry in KEYS:
        if entry["keyid"] == keyid and entry["kind"] == "transferable":
            return base64.urlsafe_b64decode(entry["public_key"] + "=")
    if len(keyid) != 44 or keyid[0] not in "BDE":
        raise MalformedKey(f'"{keyid}" is not a well-formed AID.', keyid=keyid)
    if keyid.startswith("B"):
        return verifying_key(keyid).public_bytes_raw()
    return None


def nonce(case_id: str) -> str:
    """128 bits, as the profile asks a signer to emit — deterministic here so the bytes are fixed."""
    return b64url(hashlib.sha256(case_id.encode()).digest()[:16])


def body_bytes(body: str | None) -> bytes | None:
    return None if body is None else body.encode("utf-8")


# --- signing ---

def signed_request(case_id, *, keyid=CONTROLLER_AID, key=None, method="POST",
                   url=f"{HOST}/identifiers", headers=None, body=BODY, covered=None,
                   created=AT, expires=None, emit_alg=True, with_nonce=True):
    """A request signed as a Signify client would sign it, and the base it signed."""
    key = key or SIGNERS[keyid]
    sending = dict(headers or {})
    if emit_alg:
        sending.update(sign_request(
            key=key, method=method, url=url, headers=dict(sending), body=body_bytes(body),
            covered=covered, created=created, expires=expires, label=LABEL,
            nonce=nonce(case_id) if with_nonce else None, keyid=keyid,
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
                    covered=None, key=AGENT, keyid=AGENT_AID):
    sending = dict(headers or {})
    sending.update(sign_response(
        key=key, status=status, request=as_request(request), headers=dict(sending),
        body=body_bytes(body), covered=covered, created=AT, label=LABEL, nonce=nonce(case_id),
        keyid=keyid,
    ))
    return {"status": status, "headers": sending, "body": body}


def as_request(message) -> Request:
    return Request(method=message["method"], url=message["url"], headers=message["headers"],
                   body=body_bytes(message["body"]))


# --- running fiki as the verifier the vectors describe ---

def verify(request, response=None, *, now):
    common = dict(max_age=MAX_AGE, skew=SKEW, now=now, resolve=resolve)
    if response is not None:
        return verify_response(
            status=response["status"], headers=response["headers"],
            body=body_bytes(response["body"]), request=as_request(request),
            minimum=RESPONSE_MINIMUM, **common,
        )
    return verify_request(
        method=request["method"], url=request["url"], headers=request["headers"],
        body=body_bytes(request["body"]), minimum=REQUEST_MINIMUM, **common,
    )


def expected_base(request, response=None) -> tuple[str, str]:
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
    Ed25519PublicKey.from_public_bytes(resolve(params["keyid"])).verify(
        base64.b64decode(signature), base
    )
    return base.decode("utf-8"), signature


def accept(case_id, request, response=None, *, now=AT + 30, note):
    verdict = verify(request, response, now=now)
    base, signature = expected_base(request, response)
    case = {"id": case_id, "note": note, "request": request}
    if response is not None:
        case["response"] = response
    case["now"] = now
    case["expected"] = {
        "keyid": verdict.keyid,
        "covered": [str(component(spec)) for spec in verdict.covered],
        "base": base,
        "signature": signature,
    }
    return case


def refuse(case_id, error, request, response=None, *, now=AT + 30, note):
    try:
        verify(request, response, now=now)
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
    case["now"] = now
    case["error"] = error
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
    ]
    return {**policy_header("Signed requests a canonical verifier must ACCEPT, with the base."),
            "cases": cases}


def responses():
    post = signed_request("response-to-post:request", url=f"{HOST}/identifiers/alice/events")
    get = signed_request("response-to-get:request", method="GET",
                         url=f"{HOST}/identifiers/alice?include=state", body=None)
    cases = [
        accept("response-to-post", post, signed_response("response-to-post", post),
               note="A response binds @status, its own body, and the request's method, path, "
                    "query and content-digest, each marked req."),
        accept("response-to-get", get, signed_response("response-to-get", get),
               note="The request had no body, so no \"content-digest\";req."),
        accept("response-without-a-body", post, signed_response(
            "response-without-a-body", post, status=204, body=None),
            note="A bodiless response covers no content-digest of its own."),
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
    add("two-labels", "malformed-signature-label",
        tamper(post, "Signature-Input", "",
               "other=" + post["headers"]["Signature-Input"].split("=", 1)[1] + ", "),
        note="Canonical mode carries exactly one signature.")
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
        "query-not-covered", covered=["@method", "@path", "content-digest"]),
        note="Validly signed over too little: @query is in the minimum set.")
    add("content-length-body-without-digest", "insufficient-coverage", {**signed_request(
        "content-length-body-without-digest", body=None, headers={"Content-Length": str(len(BODY.encode()))}),
        "body": BODY},
        note="Content-Length above zero means a body, and the body's digest is not covered.")
    add("chunked-body-without-digest", "insufficient-coverage", {**signed_request(
        "chunked-body-without-digest", body=None, headers={"Transfer-Encoding": "chunked"}),
        "body": BODY},
        note="Any Transfer-Encoding means a body.")
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
    add("response-status-altered", "signature-mismatch", asked, {**answer, "status": 201},
        note="The status was changed in transit.")
    add("response-body-swapped", "digest-mismatch", asked, {**answer, "body": '{"done": false}'},
        note="The response body was replaced.")
    add("response-to-a-different-path", "signature-mismatch",
        {**asked, "url": f"{HOST}/identifiers/bob/events"}, answer,
        note="A response recorded for one request, replayed against another path.")
    add("response-missing-a-req-component", "insufficient-coverage", asked, signed_response(
        "response-missing-a-req-component", asked,
        covered=["@status", req("@method"), req("@query"), "content-digest",
                 req("content-digest")]),
        note="\"@path\";req is in the response minimum set.")
    add("response-missing-the-requests-digest", "insufficient-coverage", asked,
        signed_response("response-missing-the-requests-digest", asked,
                        covered=["@status", req("@method"), req("@path"), req("@query"),
                                 "content-digest"]),
        note="The request had a body, so the response must cover \"content-digest\";req.")
    add("response-body-without-digest", "insufficient-coverage", asked, {**signed_response(
        "response-body-without-digest", asked, body=None, headers={"Content-Length": "14"}),
        "body": '{"done": true}'},
        note="A response body whose digest is not covered.")
    add("response-duplicate-ignoring-parameter-order", "duplicate-component", asked,
        tamper(answer, "Signature-Input", '"content-digest";req',
               '"content-digest";req;sf "content-digest";sf;req'),
        note="Duplicate detection ignores parameter order, and it precedes unsupported-component "
             "(sf) in section 9.")
    add("unsigned-response", "missing-signature", asked,
        without(answer, "Signature", "Signature-Input"),
        note="Section 8: a client that sent a canonical request refuses an unsigned response "
             "(an unsigned 401 is the one exception, and is not a verification).")

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
    try:
        sign_request(key=CONTROLLER, method="POST", url=f"{HOST}/identifiers", body=BODY.encode(),
                     covered=cases[-1]["covered"], keyid=CONTROLLER_AID)
    except FikiError as ex:
        if CODES[type(ex).__name__] != "uncovered-body":
            raise SystemExit(f"sign-body-without-digest: fiki reports {type(ex).__name__}")
    else:
        raise SystemExit("sign-body-without-digest: fiki signed it")

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

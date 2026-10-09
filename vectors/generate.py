#!/usr/bin/env python3
"""Regenerate the shared conformance vectors (``this.i`` @5gf6r08f).

Run from the repository root: ``python3 vectors/generate.py``.

These vectors are fiki's second oracle, covering what RFC 9421's Appendix B cannot — the AID lens,
``@query``, ``Content-Digest``, and the refusals. They are generated from the Python implementation
because there is nowhere else they could come from; the guard against that being circular is that
every value here which *can* be corroborated externally is, and is labelled so:

* the RFC B.2.6 case is the RFC's own, key and base and signature alike;
* the two AIDs are the strings keripy's ``Signer``/``Verfer`` independently produce for the same
  seeds, which heti's suite re-checks (heti tick ~36af).

Nothing gates regeneration when the default covered set changes, so each file records the covered
set and the fiki version it was generated under. A port whose failure is a covered-set change
rather than a bug should be able to see that from the file.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import http_sfv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "py" / "src"))

from fiki import (  # noqa: E402
    DEFAULT_COVERED,
    MAX_FIELD_BYTES,
    RESPONSE_MINIMUM,
    Key,
    Request,
    sign_request,
    sign_response,
    signature_base,
)
from fiki.messages import content_digest  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rfc8032  # noqa: E402  RFC 8032 section 6, verbatim: the independent Ed25519 oracle

RFC_SEED = base64.urlsafe_b64decode("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU" + "=")
SEED_A = bytes(range(32))
SEED_B = bytes(range(1, 33))

# The conformance contract's own version (`this.i` @4fhrre0m). A monotonic integer rather than a
# semantic version, because there is no meaningful minor here: an implementation either satisfies
# these vectors or it does not, and even ADDING a case is breaking for an implementation that
# already shipped. Format 2 is the 0.8.0 cross-port sweep (`this.i` @5zrf8gjk): ports, IP-literals,
# strict RFC 8941, the input bounds, raw field values, weak keys, and the verdict's keyid. Format 3
# (`this.i` @524c8qgv) makes the verifier fail closed by default: every accept and refusal case
# states the verifier's `minimum` ("default", null for the explicit opt-out, or a list) and its
# `authorities` (null or a list), since authorities is now a required decision. Bump it whenever
# the behaviour these files require changes — a covered-set default, an error name, a refusal
# that becomes an acceptance. Every port exports the format it
# satisfies and asserts the two agree, so a port running newer vectors fails loudly rather than
# passing a subset and reporting conformance it does not have.
VECTORS_FORMAT = 3

# The verifier's default minimum (@524c8qgv), stated here rather than imported so that these
# files say what the contract is, not what fiki-py happens to do. Content-digest joins it whenever
# the request has a body.
DEFAULT_MINIMUM = ["@method", "@authority", "@path", "@query"]

HEADER = {
    "about": "Shared conformance vectors for fiki. Every implementation runs these.",
    "vectors_format": VECTORS_FORMAT,
    "generated_by": "vectors/generate.py",
    "default_covered": list(DEFAULT_COVERED),
    "default_minimum": DEFAULT_MINIMUM,
}


def keyid_of(key: Key) -> str:
    from fiki.messages import _keyid

    return _keyid(key.aid)


# --- the Ed25519 equation (@524c8qgv) ---
#
# RFC 8032 section 5.1.7 permits the cofactored check [8][S]B = [8]R + [8][k]A' and the
# cofactorless [S]B = R + [k]A'; fiki pins the cofactorless one. These signatures tell them
# apart. Each is checked here against RFC 8032's own verify() (cofactorless), a cofactored check
# built from the same RFC code, and OpenSSL through cryptography, before it is written.

_IDENTITY = (0, 1, 1, 0)


def _torsion8():
    """A point of order 8, found as [q]P for a curve point P rather than taken from memory."""
    for n in range(1, 1000):
        point = rfc8032.point_decompress(hashlib.sha256(b"fiki-torsion-%d" % n).digest())
        if point is None:
            continue
        torsion = rfc8032.point_mul(rfc8032.q, point)
        if not rfc8032.point_equal(rfc8032.point_mul(4, torsion), _IDENTITY):
            return torsion
    raise AssertionError("no point of order 8 found")


def _cofactored(public: bytes, msg: bytes, signature: bytes) -> bool:
    A = rfc8032.point_decompress(public)
    R = rfc8032.point_decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    h = rfc8032.sha512_modq(signature[:32] + public + msg)
    left = rfc8032.point_mul(8, rfc8032.point_mul(s, rfc8032.G))
    right = rfc8032.point_mul(8, rfc8032.point_add(R, rfc8032.point_mul(h, A)))
    return rfc8032.point_equal(left, right)


def _openssl_accepts(public: bytes, msg: bytes, signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, msg)
    except InvalidSignature:
        return False
    return True


def _mixed_sign(seed: bytes, public: bytes, msg: bytes, *, torsion_r, want_cofactorless: bool):
    """A signature by ``seed`` that the cofactored check accepts and the cofactorless one
    accepts exactly when ``want_cofactorless``, varying the nonce until it does."""
    a, prefix = rfc8032.secret_expand(seed)
    for counter in range(1000):
        r = rfc8032.sha512_modq(prefix + msg + b"fiki-mixed-%d" % counter)
        R = rfc8032.point_mul(r, rfc8032.G)
        if torsion_r is not None:
            R = rfc8032.point_add(R, torsion_r)
        Rs = rfc8032.point_compress(R)
        h = rfc8032.sha512_modq(Rs + public + msg)
        signature = Rs + int.to_bytes((r + h * a) % rfc8032.q, 32, "little")
        if rfc8032.verify(public, msg, signature) == want_cofactorless:
            assert _cofactored(public, msg, signature), "the cofactored check must accept it"
            assert _openssl_accepts(public, msg, signature) == want_cofactorless, \
                "OpenSSL must agree with RFC 8032's verify()"
            return signature
    raise AssertionError("no signature of the wanted kind found")


def _mixed_key(seed: bytes) -> bytes:
    """seed's public key plus a point of order 8: of mixed order, so not refused as small-order."""
    from fiki.keys import _decode_point, _small_order

    a, _ = rfc8032.secret_expand(seed)
    mixed = rfc8032.point_compress(rfc8032.point_add(rfc8032.point_mul(a, rfc8032.G), _torsion8()))
    point = _decode_point(mixed)
    assert point is not None and not _small_order(*point), "fiki must not refuse this key's shape"
    return mixed


def mixed_order_refusals():
    """(case id, signature-for-base, keyid, note) for signatures only the cofactored check takes."""
    honest = rfc8032.secret_to_public(SEED_A)
    mixed = _mixed_key(SEED_A)
    return [
        ("cofactored-only-signature-under-an-honest-key",
         lambda base: base64.b64encode(_mixed_sign(SEED_A, honest, base, torsion_r=_torsion8(),
                                                   want_cofactorless=False)).decode("ascii"),
         b64url(honest),
         "R carries a point of order 8. [8][S]B = [8]R + [8][k]A holds and [S]B = R + [k]A "
         "does not, so the cofactorless check fiki pins refuses it (RFC 8032 section 5.1.7)."),
        ("mixed-order-key-the-cofactorless-check-refuses",
         lambda base: base64.b64encode(_mixed_sign(SEED_A, mixed, base, torsion_r=None,
                                                   want_cofactorless=False)).decode("ascii"),
         b64url(mixed),
         "The key is SEED_A's plus a point of order 8, and k is not a multiple of 8, so only the "
         "cofactored equation holds."),
    ]


def mixed_order_accepts(signed_at: int):
    """(case id, seed, signed headers, note) for a mixed-order key the cofactorless check takes."""
    mixed = _mixed_key(SEED_A)
    keyid = b64url(mixed)
    url = "https://api.example.com/x"
    base = signature_base(method="GET", url=url, headers={}, covered=DEFAULT_COVERED,
                          created=signed_at, keyid=keyid, alg="ed25519")
    signature = _mixed_sign(SEED_A, mixed, base, torsion_r=None, want_cofactorless=True)
    params = base.decode("utf-8").rsplit('"@signature-params": ', 1)[1]
    headers = {"Signature-Input": f"sig={params}",
               "Signature": f"sig=:{base64.b64encode(signature).decode('ascii')}:"}
    return [("mixed-order-key-the-cofactorless-check-accepts", SEED_A, headers,
             "The same mixed-order key, with a k that is a multiple of 8, so both equations "
             "hold; a port that refuses every mixed-order key fails here.")]


def non_canonical_r_signature(url: str) -> str:
    """SEED_A's signature over the default GET base with R the identity spelled y = p + 1."""
    key = Key.from_seed(SEED_A)
    public = rfc8032.secret_to_public(SEED_A)
    base = signature_base(method="GET", url=url, headers={}, covered=DEFAULT_COVERED,
                          created=1700000000, keyid=b64url(public), alg="ed25519")
    a, _ = rfc8032.secret_expand(SEED_A)
    r_bytes = int.to_bytes(rfc8032.p + 1, 32, "little")
    h = rfc8032.sha512_modq(r_bytes + public + base)
    signature = r_bytes + int.to_bytes(h * a % rfc8032.q, 32, "little")
    assert not rfc8032.verify(public, base, signature) and not _openssl_accepts(public, base, signature)
    assert key.aid  # the same key fiki's signer uses
    return base64.b64encode(signature).decode("ascii")


def torsion_r_accept(signed_at: int):
    """A mixed-order key and an R with torsion that cancels, so the cofactorless equation holds."""
    mixed = _mixed_key(SEED_A)
    keyid = b64url(mixed)
    base = signature_base(method="GET", url="https://api.example.com/x", headers={},
                          covered=DEFAULT_COVERED, created=signed_at, keyid=keyid, alg="ed25519")
    a, prefix = rfc8032.secret_expand(SEED_A)
    torsion = _torsion8()
    for counter in range(2000):
        r = rfc8032.sha512_modq(prefix + base + b"fiki-torsion-r-%d" % counter)
        for j in range(1, 8):
            R = rfc8032.point_add(rfc8032.point_mul(r, rfc8032.G), rfc8032.point_mul(j, torsion))
            Rs = rfc8032.point_compress(R)
            h = rfc8032.sha512_modq(Rs + mixed + base)
            if (j + h) % 8 or h % 8 == 0:
                continue
            signature = Rs + int.to_bytes((r + h * a) % rfc8032.q, 32, "little")
            assert rfc8032.verify(mixed, base, signature) and _openssl_accepts(mixed, base, signature)
            params = base.decode("utf-8").rsplit('"@signature-params": ', 1)[1]
            return {"Signature-Input": f"sig={params}",
                    "Signature": f"sig=:{base64.b64encode(signature).decode('ascii')}:"}
    raise AssertionError("no torsion-R signature found")


def by_hand_signer(key: Key):
    """Headers for a GET signed over a base built here line by line, not by fiki's signer.

    For what fiki's signer refuses to emit or always emits one way: a parameter order other than
    fiki's, no created, a negative one, an alias keyid, an uppercase alg, a component a caller
    names. The component lines come from fiki's signature_base over a well-formed twin, and only
    the @signature-params line is written here, so the case tests one thing.
    """

    def build(url, *, keyid=None, created=1700000000, alg="ed25519", order=None,
              params_override=None, extra_covered=(), headers=None):
        covered = list(DEFAULT_COVERED) + list(extra_covered)
        twin = signature_base(method="GET", url=url, headers=headers or {}, covered=covered,
                              created=1700000000, keyid=keyid_of(key), alg="ed25519")
        lines, _ = twin.decode("utf-8").rsplit('"@signature-params": ', 1)
        inner = "(" + " ".join(f'"{c}"' for c in covered) + ")"
        values = {"created": None if created is None else f"created={created}",
                  "alg": f'alg="{alg}"', "keyid": f'keyid="{keyid_of(key) if keyid is None else keyid}"'}
        params = [values[name] for name in (order or ("created", "alg", "keyid")) if values[name]]
        if params_override is not None:
            params = [params_override] + [values["alg"], values["keyid"]]
        value = inner + "".join(";" + p for p in params)
        base = (lines + '"@signature-params": ' + value).encode("utf-8")
        sent = dict(headers or {})
        sent["Signature-Input"] = "sig=" + value
        sent["Signature"] = f"sig=:{base64.b64encode(key.sign(base)).decode()}:"
        return sent

    return build


B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def padded_url(size: int) -> str:
    prefix = "https://api.example.com/"
    return prefix + "p" * (size - len(prefix))


def sha512_digest(body: bytes) -> str:
    return "sha-512=:" + base64.b64encode(hashlib.sha512(body).digest()).decode() + ":"


def digest_signed_twice(key: Key, url: str, *, good_first: bool) -> dict:
    """A POST whose Content-Digest names sha-256 twice, one right and one wrong, signed over it."""
    body = b'{"hello": "world"}'
    good, bad = content_digest(body), "sha-256=:" + "A" * 43 + "=:"
    digest = f"{good}, {bad}" if good_first else f"{bad}, {good}"
    base = signature_base(method="POST", url=url, headers={"Content-Digest": digest},
                          covered=tuple(DEFAULT_COVERED) + ("content-digest",), created=1700000000,
                          keyid=keyid_of(key), alg="ed25519")
    return {"Content-Digest": digest,
            "Signature-Input": "sig=" + base.decode().rsplit('"@signature-params": ', 1)[1],
            "Signature": f"sig=:{base64.b64encode(key.sign(base)).decode()}:"}


def aid_of_raw(raw: bytes) -> str:
    from fiki import to_aid

    return to_aid(raw)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unchecked(key, *, method, url, headers, covered, created, keyid, label="sig", nonce=None):
    """Sign over the base directly, as sign_request would, without its checks on the caller.

    For a message whose defect the signer refuses to produce, such as a Content-Digest the body
    contradicts (@5zrf8gjk), which a verifier must still refuse when another signer sends it. The
    bytes are what sign_request emits for the same inputs: the same base, the same parameter
    order, alg included.
    """
    sent = dict(headers)
    base = signature_base(method=method, url=url, headers=sent, covered=covered, created=created,
                          keyid=keyid, alg="ed25519", nonce=nonce)
    params = base.decode("utf-8").rsplit('"@signature-params": ', 1)[1]
    sent["Signature-Input"] = f"{label}={params}"
    sent["Signature"] = f"{label}=:{base64.b64encode(key.sign(base)).decode('ascii')}:"
    return sent


def padded_to(size: int, prefix: str, suffix: str = "") -> str:
    """prefix + filler + suffix of exactly ``size`` bytes, the filler a run of 'A'.

    Used inside an sf-string, where any length is well formed.
    """
    return prefix + "A" * (size - len(prefix) - len(suffix)) + suffix


def base_case(case_id, *, seed, method, url, headers, covered, created, keyid, alg=None, note=None):
    base = signature_base(
        method=method, url=url, headers=headers, covered=covered,
        created=created, keyid=keyid, alg=alg,
    )
    signature = Key.from_seed(seed).sign(base)
    case = {
        "id": case_id,
        "seed_hex": seed.hex(),
        "method": method,
        "url": url,
        "headers": headers,
        "covered": list(covered),
        "created": created,
        "keyid": keyid,
        "base": base.decode("utf-8"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    if alg is not None:
        case["alg"] = alg
    if note is not None:
        case["note"] = note
    return case


def aid_lens():
    cases = []
    for case_id, seed, note in [
        ("keripy-cross-checked", SEED_A,
         "keripy's Signer produces this same AID for this seed; heti's suite re-checks it."),
        ("rfc-9421-b-1-4", RFC_SEED,
         "The RFC's own ed25519 test key, seen through fiki's lens."),
        ("second-key", SEED_B, None),
    ]:
        key = Key.from_seed(seed)
        entry = {
            "id": case_id,
            "seed_hex": seed.hex(),
            "public_key_hex": base64.urlsafe_b64decode(
                keyid_of(key) + "=" * (-len(keyid_of(key)) % 4)
            ).hex(),
            "aid": key.aid,
            "keyid": keyid_of(key),
        }
        if note:
            entry["note"] = note
        cases.append(entry)
    return {**HEADER, "about": "A seed to its non-transferable AID and to its keyid.",
            "cases": cases}


def signature_bases():
    key = Key.from_seed(SEED_A)
    keyid = keyid_of(key)
    body = b'{"hello": "world"}'
    cases = [
        base_case(
            "rfc-9421-b-2-6",
            seed=RFC_SEED,
            method="POST",
            url="https://example.com/foo?param=Value&Pet=dog",
            headers={
                "Date": "Tue, 20 Apr 2021 02:07:55 GMT",
                "Content-Type": "application/json",
                "Content-Length": "18",
            },
            covered=("date", "@method", "@path", "@authority", "content-type", "content-length"),
            created=1618884473,
            keyid="test-key-ed25519",
            note="Verbatim from RFC 9421 Appendix B.2.6. Externally anchored: no Bakobo party "
                 "authored this base or this signature.",
        ),
        base_case(
            "default-covered-with-query",
            seed=SEED_A,
            method="GET",
            url="https://api.example.com/things?limit=1&sort=name",
            headers={},
            covered=DEFAULT_COVERED,
            created=1700000000,
            keyid=keyid,
            alg="ed25519",
            note="The covered set the RFC's own vectors never exercise.",
        ),
        base_case(
            "query-absent-is-a-bare-question-mark",
            seed=SEED_A,
            method="GET",
            url="https://api.example.com/things",
            headers={},
            covered=DEFAULT_COVERED,
            created=1700000000,
            keyid=keyid,
            alg="ed25519",
            note="RFC 9421 section 2.2.7: a request with no query still binds 'no query'.",
        ),
        base_case(
            "percent-encoding-is-not-decoded",
            seed=SEED_A,
            method="GET",
            url="https://api.example.com/p?baz=bat%2Dman",
            headers={},
            covered=("@method", "@path", "@query"),
            created=1700000000,
            keyid=keyid,
            alg="ed25519",
        ),
        base_case(
            "body-bound-by-content-digest",
            seed=SEED_A,
            method="POST",
            url="https://api.example.com/things",
            headers={"Content-Digest": content_digest(body)},
            covered=tuple(DEFAULT_COVERED) + ("content-digest",),
            created=1700000000,
            keyid=keyid,
            alg="ed25519",
            note="The other thing the RFC's ed25519 vector never exercises.",
        ),
        base_case(
            "relative-url-takes-authority-from-the-host-header",
            seed=SEED_A,
            method="GET",
            url="/things?limit=1",
            headers={"Host": "API.example.com"},
            covered=DEFAULT_COVERED,
            created=1700000000,
            keyid=keyid,
            alg="ed25519",
            note="The shape a server-side verifier has, and the shape heti's vanilla dialect "
                 "delegates in. The host is lowercased; no port is stripped, because with no "
                 "scheme no port is a default port.",
        ),
        base_case(
            "non-default-port-is-kept",
            seed=SEED_A,
            method="GET",
            url="https://api.example.com:8443/things",
            headers={},
            covered=("@authority",),
            created=1700000000,
            keyid=keyid,
            alg="ed25519",
        ),
        base_case(
            "port-with-leading-zeros-that-is-the-default",
            seed=SEED_A, method="GET", url="https://api.example.com:000443/things", headers={},
            covered=("@authority",), created=1700000000, keyid=keyid, alg="ed25519",
            note="A port is any run of ASCII digits, read as a number: :000443 is 443, the "
                 "default for https, so it is dropped (@5zrf8gjk).",
        ),
        base_case(
            "port-with-leading-zeros-is-read-as-a-number",
            seed=SEED_A, method="GET", url="https://api.example.com:08443/things", headers={},
            covered=("@authority",), created=1700000000, keyid=keyid, alg="ed25519",
            note="Read as a number, so it is written back without its leading zero.",
        ),
        base_case(
            "ipv6-literal-keeps-its-brackets",
            seed=SEED_A, method="GET", url="https://[2001:DB8::1]:8443/things", headers={},
            covered=("@authority",), created=1700000000, keyid=keyid, alg="ed25519",
            note="RFC 3986 section 3.2.2 makes the brackets part of the host; it is lowercased "
                 "like any other.",
        ),
        base_case(
            "ipvfuture-literal-keeps-its-brackets",
            seed=SEED_A, method="GET", url="https://[v1.Example]/things", headers={},
            covered=("@authority",), created=1700000000, keyid=keyid, alg="ed25519",
            note="An IPvFuture literal has no colon to tell it by, and keeps its brackets too.",
        ),
        base_case(
            "method-is-any-token-kept-as-sent",
            seed=SEED_A, method="M-Search", url="https://api.example.com/things", headers={},
            covered=("@method", "@path"), created=1700000000, keyid=keyid, alg="ed25519",
            note="A method is an RFC 9110 token, and its case is kept as given (@22g0xkr8).",
        ),
        base_case(
            "field-value-is-trimmed-of-sp-and-htab",
            seed=SEED_A, method="GET", url="https://api.example.com/things",
            headers={"X-Note": " \t value \t "}, covered=("@method", "x-note"),
            created=1700000000, keyid=keyid, alg="ed25519",
            note="RFC 9110 section 5.5: SP and HTAB around a field value are not part of it.",
        ),
    ]
    # Written out by hand from RFC 9112 section 3.2.1 rather than produced by fiki-py's
    # signature_base, which read this target as a network-path reference until format 3: a vector
    # generated by the code under test would have pinned that bug (@524c8qgv).
    params = ('("@method" "@authority" "@path" "@query");created=1700000000;alg="ed25519";'
              f'keyid="{keyid}"')
    by_hand = (f'"@method": GET\n"@authority": victim.example\n"@path": //evil.example/p\n'
               f'"@query": ?x=1\n"@signature-params": {params}').encode("utf-8")
    cases.append({
        "id": "origin-form-path-with-a-leading-double-slash",
        "seed_hex": SEED_A.hex(),
        "method": "GET",
        "url": "//evil.example/p?x=1",
        "headers": {"Host": "victim.example"},
        "covered": list(DEFAULT_COVERED),
        "created": 1700000000,
        "keyid": keyid,
        "base": by_hand.decode("utf-8"),
        "signature": base64.b64encode(Key.from_seed(SEED_A).sign(by_hand)).decode("ascii"),
        "alg": "ed25519",
        "note": "A target that begins with a slash is origin-form (RFC 9112 section 3.2.1): "
                "@path is //evil.example/p and @authority is the Host header (@524c8qgv). Read "
                "as a network-path reference, the sender would choose the authority.",
    })
    return {**HEADER, "about": "Signature bases and the signatures over them, byte for byte.",
            "cases": cases}


def refusals():
    key = Key.from_seed(SEED_A)
    url = "https://api.example.com/things?limit=1&sort=name"
    body = b'{"hello": "world"}'

    def signed(**kwargs):
        args = dict(key=key, method="POST", url=url, headers={}, body=body,
                    created=1700000000)
        args.update(kwargs)
        headers = dict(args.get("headers") or {})
        headers.update(sign_request(**args))
        return headers

    cases = []

    def add(case_id, error, *, method="POST", target=url, headers=None, body_text='{"hello": "world"}',
            note=None, max_age=None, now=None, minimum="default", authorities=None,
            expected_aid=None):
        case = {
            "id": case_id,
            "method": method,
            "url": target,
            "headers": headers,
            "body": body_text,
            "max_age": max_age,
            "now": now,
            "minimum": minimum,
            "authorities": authorities,
            "expected_aid": expected_aid,
            "error": error,
        }
        if note:
            case["note"] = note
        cases.append(case)

    add("rewritten-query", "SignatureMismatch", headers=signed(),
        target="https://api.example.com/things?limit=1000000&sort=name",
        note="The headline case. heti's KERI dialect cannot see this at all.")
    add("rewritten-host", "SignatureMismatch", headers=signed(),
        target="https://evil.example.com/things?limit=1&sort=name")
    add("rewritten-method", "SignatureMismatch", headers=signed(), method="DELETE")
    add("swapped-body", "DigestMismatch", headers=signed(), body_text='{"hello": "goodbye"}')
    add("covered-digest-with-no-body", "DigestMismatch", headers=signed(), body_text=None,
        note="Fail closed: a verifier that cannot check the digest has not checked the body.")

    two_labels = signed()
    _, rest = two_labels["Signature-Input"].split("=", 1)
    two_labels["Signature-Input"] = f"{two_labels['Signature-Input']},other={rest}"
    add("two-signature-labels", "MalformedSignatureLabel", headers=two_labels)

    wrong_alg = signed()
    wrong_alg["Signature-Input"] = wrong_alg["Signature-Input"].replace(
        ';alg="ed25519"', ';alg="rsa-pss-sha512"'
    )
    add("algorithm-other-than-ed25519", "UnsupportedAlgorithm", headers=wrong_alg)

    bad_keyid = signed()
    keyid = bad_keyid["Signature-Input"].split('keyid="')[1].split('"')[0]
    bad_keyid["Signature-Input"] = bad_keyid["Signature-Input"].replace(keyid, "not-a-key")
    add("keyid-that-is-not-a-key", "MalformedKey", headers=bad_keyid)

    # The header-level distinctions. They exist because heti publishes a separate code for each
    # (fiki @8zw78n0v), so a port that folds them together is not interchangeable with this one.
    no_sig = signed()
    del no_sig["Signature"]
    add("no-signature-header", "MissingSignature", headers=no_sig)

    no_input = signed()
    del no_input["Signature-Input"]
    add("no-signature-input-header", "MissingSignatureInput", headers=no_input)

    bad_input = signed()
    bad_input["Signature-Input"] = "not a dictionary ((("
    add("unparsable-signature-input", "MalformedSignatureInput", headers=bad_input)

    bad_sig = signed()
    bad_sig["Signature"] = "not a dictionary ((("
    add("unparsable-signature", "MalformedSignature", headers=bad_sig)

    mismatched = signed()
    mismatched["Signature"] = "other=" + mismatched["Signature"].split("=", 1)[1]
    add("signature-labelled-differently-from-its-input", "MissingSignatureLabel", headers=mismatched)

    not_bytes = signed()
    not_bytes["Signature"] = 'sig="a string, not a byte sequence"'
    add("signature-that-is-not-a-byte-sequence", "MalformedSignatureValue", headers=not_bytes)

    no_keyid = signed()
    no_keyid["Signature-Input"] = (
        no_keyid["Signature-Input"].split(";keyid=")[0] + ';alg="ed25519"'
    )
    add("no-keyid-and-no-preregistered-aid", "MissingKey", headers=no_keyid)

    def digest_signed(digest):
        """A request signed over a Content-Digest its body does not support (@5zrf8gjk)."""
        return unchecked(key, method="POST", url=url, headers={"Content-Digest": digest},
                         covered=tuple(DEFAULT_COVERED) + ("content-digest",),
                         created=1700000000, keyid=keyid_of(key))

    add("content-digest-fiki-cannot-compute", "MalformedDigest",
        headers=digest_signed("sha-1=:AAAA:"))

    # Freshness (@67shl6c5). These carry an explicit `now`, because a conformance vector cannot
    # pin a check against a moving clock — a port that had to fake time to run them would be
    # testing its own fake rather than fiki's rule.
    signed_at = 1700000000
    add("older-than-max-age", "SignatureTooOld", headers=signed(created=signed_at),
        max_age=300, now=signed_at + 400,
        note="The verifier's own policy, which it had to state to get: max_age has no default.")
    add("created-in-the-future-beyond-skew", "SignatureTooOld",
        headers=signed(created=signed_at), max_age=300, now=signed_at - 60,
        note="A broken clock, or a signer buying themselves a longer window.")
    add("past-the-signers-own-expires", "SignatureExpired",
        headers=signed(created=signed_at, expires=signed_at + 60),
        max_age=None, now=signed_at + 120,
        note="Enforced even with max_age=None: expires is the SIGNER's declaration, and a "
             "verifier that accepts one without checking it is selling a guarantee nobody bought.")

    # --- format 2: the 0.8.0 cross-port sweep (@5zrf8gjk) ---

    # A port is any run of ASCII digits, read as a number in 0..65535. A URL handed to the verifier
    # with one that is not is a base that cannot be built, never an uncaught exception.
    get = signed(method="GET", body=None)
    add("port-out-of-range", "SignatureMismatch", method="GET", headers=get, body_text=None,
        target="https://api.example.com:65536/things?limit=1&sort=name",
        note="65536 is not a port, so @authority cannot be built: a base that cannot be built "
             "is a signature mismatch (profile section 9).")
    add("port-that-is-not-a-number", "SignatureMismatch", method="GET", headers=get,
        body_text=None, target="https://api.example.com:44x/things?limit=1&sort=name")
    literal = signed(method="GET", body=None, url="https://[2001:db8::1]/things")
    add("text-after-an-ip-literal", "SignatureMismatch", method="GET", headers=literal,
        body_text=None, target="https://[2001:db8::1]x/things",
        note="Nothing but :port may follow an IP-literal's closing bracket.")
    # Signed over the base a lenient port would build, since fiki will not build it, so only the
    # IP-literal check can refuse it.
    forged = signature_base(method="GET", url="https://[::1]/things", headers={},
                            covered=["@method", "@authority", "@path", "@query"], created=1700000000,
                            keyid=keyid_of(key), alg="ed25519")
    forged = forged.replace(b'"@authority": [::1]', b'"@authority": [not-an-ip]')
    add("ip-literal-that-is-not-an-address", "SignatureMismatch", method="GET", body_text=None,
        target="https://[not-an-ip]/things",
        headers={"Signature-Input": "sig=" + forged.decode().rsplit('"@signature-params": ', 1)[1],
                 "Signature": f"sig=:{base64.b64encode(key.sign(forged)).decode()}:"},
        note="An IP-literal holds an IPv6 address or IPvFuture (RFC 3986 section 3.2.2). The "
             "signature is good over the base a port without that check would build.")
    add("port-of-thousands-of-digits", "SignatureMismatch", method="GET", headers=get,
        body_text=None, target="https://api.example.com:" + "0" * 5000 + "65536/things",
        note="65536 behind 5,000 leading zeros is still out of range, and is refused without "
             "converting the digits.")

    # A covered field value is checked for line breaks and controls as received, and only then
    # trimmed of SP and HTAB, so a line break at its edge is refused like one inside it.
    noted = signed(method="GET", body=None, headers={"X-Note": "value"},
                   covered=["@method", "@authority", "@path", "@query", "x-note"])
    add("covered-field-with-a-line-break-at-its-edge", "SignatureMismatch", method="GET",
        headers={**noted, "X-Note": "value\r\n"}, body_text=None,
        note="Signed over 'value', received as 'value' CR LF. Trimming the line break before "
             "checking for it would verify this.")

    # Public keys that are not ones an honest signer holds, on the raw-keyid path.
    for case_id, raw, note in [
        ("small-order-raw-keyid", b"\x01" + bytes(31),
         "The identity point: under it a signature of 0x01 and 63 zero bytes verifies over any "
         "message, so it is refused before the signature is examined."),
        ("raw-keyid-whose-y-is-not-below-p", ((1 << 255) - 19).to_bytes(32, "little"),
         "y = p is not the canonical encoding of any point (RFC 8032 section 5.1.3)."),
    ]:
        forged = signed(method="GET", body=None, keyid=b64url(raw))
        forged["Signature"] = f"sig=:{base64.b64encode(b'\x01' + bytes(63)).decode()}:"
        add(case_id, "MalformedKey", method="GET", headers=forged, body_text=None, note=note)

    # Strict RFC 8941. Each defect sits in a Content-Digest member fiki ignores, beside a
    # sha-256 member that matches, so a lenient parser accepts the request outright.
    good = content_digest(body)
    for case_id, member, note in [
        ("integer-of-sixteen-digits", "x=1234567890123456",
         "RFC 8941 section 3.3.1: an integer has at most fifteen digits."),
        ("decimal-without-a-fractional-digit", "x=1.",
         "RFC 8941 section 4.2.4: a decimal has at least one digit after its point."),
        ("byte-sequence-missing-its-padding", "x=:QQ:",
         "Base64 padded to a multiple of four characters is the only spelling fiki decodes."),
        ("byte-sequence-with-incomplete-padding", "x=:QQ=:", None),
        ("byte-sequence-of-padding-alone", "x=:=:", None),
        ("byte-sequence-with-padding-in-the-middle", "x=:QQ==QUFB:",
         "RFC 4648 section 3.3: padding only at the end (@2g4xxev9)."),
    ]:
        add(case_id, "MalformedDigest", headers=digest_signed(f"{good}, {member}"), note=note)
    broken = signed()
    value = broken["Signature"].split("=:", 1)[1]
    broken["Signature"] = f"sig=:{value[:20]}\r\n{value[20:]}"
    add("byte-sequence-with-a-line-break", "MalformedSignature", headers=broken,
        note="A character outside the base64 alphabet, which some decoders silently skip.")

    # Input bounds (ticks 65q7, 6mhg), size before shape. Each over-limit header is otherwise one
    # a verifier accepts, so a port without the bound accepts it rather than refusing it.
    limit = MAX_FIELD_BYTES + 1
    long_nonce = signed(nonce="A" * (limit - len(signed()["Signature-Input"]) - len(';nonce=""')))
    assert len(long_nonce["Signature-Input"]) == limit
    add("signature-input-over-8192-bytes", "MalformedSignatureInput", headers=long_nonce,
        note="8193 bytes, made so by a long nonce the signer chose; one byte shorter verifies.")
    long_signature = signed()
    long_signature["Signature"] = padded_to(
        limit, long_signature["Signature"] + ';x="', '"')
    add("signature-over-8192-bytes", "MalformedSignature", headers=long_signature,
        note="8193 bytes, made so by a string parameter on the signature that nothing reads.")
    add("content-digest-over-8192-bytes", "MalformedDigest",
        headers=digest_signed(padded_to(limit, f'{good}, x="', '"')),
        note="8193 bytes, made so by a member whose algorithm fiki ignores. A signer that "
             "measures the digest it is handed refuses to sign it, so this one was signed over "
             "the base.")
    crowded = signed()
    crowded["Signature"] += "".join(f", x{i}=:AAAA:" for i in range(16))
    add("dictionary-of-seventeen-members", "MalformedSignature", headers=crowded,
        note="At most 16 members in any of the three headers. Sixteen would be "
             "MalformedSignatureLabel, as two would.")
    fields = {f"x-h{i}": str(i) for i in range(62)}
    add("inner-list-of-sixty-five-components", "MalformedSignatureInput", method="GET",
        headers=signed(method="GET", body=None, headers=fields,
                       covered=["@method", "@path", "@query", *fields]),
        body_text=None, note="At most 64 items in an inner list; this one verifies otherwise.")
    add("item-with-seventeen-parameters", "MalformedDigest",
        headers=digest_signed(good + "".join(f";p{i}" for i in range(17))),
        note="At most 16 parameters on an item; parameters on a digest member are ignored "
             "otherwise.")

    # --- format 3: the verifier fails closed by default (@524c8qgv) ---

    get_default = signed(method="GET", body=None)
    add("uncovered-body", "InsufficientCoverage", method="GET", headers=get_default,
        note="Signed with no body, received with one: under the default minimum a body needs a "
             "covered content-digest. Before format 3 this verified.")
    add("body-announced-by-content-length-only", "InsufficientCoverage", method="GET",
        headers={**get_default, "Content-Length": "18"}, body_text=None,
        note="The caller did not pass the body, but the headers say there is one, which counts "
             "(the profile's body test).")
    add("uncovered-digest-that-contradicts-the-body", "InsufficientCoverage", method="GET",
        headers={**get_default, "Content-Digest": "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"},
        note="An uncovered Content-Digest attests to nothing, so it cannot stand in for coverage.")
    for case_id, covered, missing in [
        ("default-minimum-without-query", ["@method", "@authority", "@path"], "@query"),
        ("default-minimum-without-authority", ["@method", "@path", "@query"], "@authority"),
        ("default-minimum-without-method", ["@authority", "@path", "@query"], "@method"),
    ]:
        add(case_id, "InsufficientCoverage", method="GET", body_text=None,
            headers=signed(method="GET", body=None, covered=covered),
            note=f"A valid signature that does not cover {missing}, which the default minimum "
                 "requires.")
    empty = unchecked(key, method="GET", url=url, headers={}, covered=(), created=1700000000,
                      keyid=keyid_of(key))
    add("empty-covered-list", "InsufficientCoverage", method="GET", headers=empty, body_text=None,
        note="sig=() binds nothing but its own parameters, so it would authenticate any request "
             "within its freshness window.")
    # fiki will not build a base with no created, so strip it from one and sign what is left.
    with_created = signature_base(method="GET", url=url, headers={}, covered=DEFAULT_COVERED,
                                  created=1700000000, keyid=keyid_of(key), alg="ed25519")
    without = with_created.replace(b";created=1700000000", b"")
    assert without != with_created
    no_created = {
        "Signature-Input": "sig=" + without.decode().rsplit('"@signature-params": ', 1)[1],
        "Signature": f"sig=:{base64.b64encode(key.sign(without)).decode()}:",
    }
    add("no-created-under-the-default-minimum", "MalformedSignatureInput", method="GET",
        headers=no_created, body_text=None,
        note="A signature with no created replays forever; every minimum requires it (@7p9s3g9k).")
    add("minimum-opt-out-still-checks-served-authorities", "InsufficientCoverage", method="GET",
        body_text=None, minimum=None, authorities=["api.example.com"],
        headers=signed(method="GET", body=None, covered=["@method", "@path", "@query"]),
        note="Opting out of the minimum does not opt out of authorities, which require "
             "@authority (@605z9tnw).")
    add("authority-not-served", "SignatureMismatch", method="GET", body_text=None,
        authorities=["other.example"], headers=get_default,
        note="Covered and valid, but not an authority this verifier serves.")

    # A target that begins with a slash is origin-form, however many slashes follow (@524c8qgv).
    elsewhere = signed(method="GET", body=None, url="https://evil.example/p")
    add("network-path-target-is-a-path", "SignatureMismatch", method="GET", body_text=None,
        target="//evil.example/p", headers={**elsewhere, "Host": "victim.example"},
        note="Signed for evil.example. Received at victim.example as the origin-form target "
             "//evil.example/p, whose @path is //evil.example/p and whose @authority is the "
             "Host header. Ports that read it as a network-path reference let the sender "
             "choose the authority.")
    for case_id, target in [
        ("scheme-without-authority", "https:/things?limit=1&sort=name"),
        ("scheme-with-empty-authority", "https:///things?limit=1&sort=name"),
        ("authority-form-target", "api.example.com:443"),
        ("asterisk-form-target", "*"),
    ]:
        add(case_id, "SignatureMismatch", method="GET", body_text=None, target=target,
            headers={**get_default, "Host": "api.example.com"},
            note="Neither origin-form nor an absolute URI with an authority, so no base can be "
                 "built: a signature mismatch (@5zrf8gjk).")

    for case_id, target in [
        ("target-with-a-line-break", "/things\n?limit=1&sort=name"),
        ("target-with-a-tab", "/thi\tngs?limit=1&sort=name"),
        ("target-with-a-space", "/things ?limit=1&sort=name"),
        ("absolute-url-with-a-line-break", "https://api.example.com/thi\r\nngs?limit=1&sort=name"),
    ]:
        add(case_id, "SignatureMismatch", method="GET", body_text=None, target=target,
            headers={**get_default, "Host": "api.example.com"},
            note="A request target holds no space or control character. Stripping one, as some "
                 "URL parsers do, made /things LF verify as /things (review V-M5).")

    # RFC 8941 to the grammar (@524c8qgv): an sf-string holds printable ASCII only, and the
    # whitespace inside an inner list, after a parameter's semicolon, and at the start of a
    # header is SP, never HTAB.
    for case_id, raw_text in [
        ("keyid-with-a-line-break", "E\r\nkeri"),
        ("keyid-with-a-tab", "a\tb"),
        ("keyid-with-a-nul", "a\x00b"),
        ("keyid-with-a-del", "a\x7fb"),
        ("keyid-with-non-ascii", "caf\u00e9"),
    ]:
        bad = signed(method="GET", body=None)
        real = bad["Signature-Input"].split('keyid="')[1].split('"')[0]
        bad["Signature-Input"] = bad["Signature-Input"].replace(f'keyid="{real}"', f'keyid="{raw_text}"')
        assert raw_text in bad["Signature-Input"], case_id
        add(case_id, "MalformedSignatureInput", method="GET", headers=bad, body_text=None,
            note="An sf-string carries %x20-7E only (RFC 8941 section 3.3.3).")
    for case_id, mangle in [
        ("tab-between-inner-list-items", lambda v: v.replace('"@method" "@authority"', '"@method"\t"@authority"')),
        ("tab-after-a-parameter-semicolon", lambda v: v.replace(";created=", ";\tcreated=")),
        ("tab-at-the-start-of-the-header", lambda v: "\t" + v),
    ]:
        bad = signed(method="GET", body=None)
        before = bad["Signature-Input"]
        bad["Signature-Input"] = mangle(before)
        assert bad["Signature-Input"] != before, case_id
        add(case_id, "MalformedSignatureInput", method="GET", headers=bad, body_text=None,
            note="RFC 8941 sections 3.1.1, 3.1.2 and 4.2: SP only here, never HTAB.")

    # --- format 3, from the challenge of its test plan (format3-test-plan-challenge.md) ---
    query = "/things?limit=1&sort=name"
    evil = signed(method="GET", body=None, url="https://evil.example" + query)
    add("authorities-checked-against-the-target-not-host", "SignatureMismatch", method="GET",
        body_text=None, target="https://evil.example" + query,
        headers={**evil, "Host": "victim.example"}, authorities=["victim.example"],
        note="An absolute target's authority is the target's (RFC 9112 section 3.2.2), so a "
             "port that compares the Host header with authorities admits a cross-service replay.")
    add("authorities-port-is-part-of-the-authority", "SignatureMismatch", method="GET",
        body_text=None, target="https://api.example.com:8443" + query,
        headers=signed(method="GET", body=None, url="https://api.example.com:8443" + query),
        authorities=["api.example.com"],
        note="api.example.com:8443 is not api.example.com: comparing host names only would let "
             "a signature for one service replay to another port on the same host.")
    add("origin-form-host-not-served", "SignatureMismatch", method="GET", body_text=None,
        target=query, headers={**evil, "Host": "evil.example"}, authorities=["victim.example"],
        note="authorities binds an origin-form request too, whose authority is its Host.")
    for case_id, entry in [("authorities-entry-in-uppercase", "API.EXAMPLE.COM"),
                           ("authorities-entry-with-a-default-port", "api.example.com:443")]:
        add(case_id, "SignatureMismatch", method="GET", body_text=None, headers=get_default,
            authorities=[entry],
            note="Entries are compared exactly with @authority as fiki derives it: lowercase, "
                 "a default port dropped (this.i, 'authorities match exactly').")

    # Host supplies an origin-form request's authority, and is validated like any authority.
    # Each is signed over the base a port that took Host verbatim would build.
    for case_id, host in [
        ("host-with-a-port-out-of-range", "api.example.com:65536"),
        ("host-with-userinfo", "user@api.example.com"),
        ("host-that-is-a-list-of-hosts", "victim.example, evil.example"),
        ("host-with-an-ip-literal-that-is-not-an-address", "[not-an-ip]"),
        ("host-with-a-port-that-is-not-a-number", "api.example.com:44x"),
    ]:
        good_base = signature_base(method="GET", url=query, headers={"Host": "placeholder.example"},
                                   covered=DEFAULT_COVERED, created=1700000000,
                                   keyid=keyid_of(key), alg="ed25519")
        lenient = good_base.replace(b'"@authority": placeholder.example',
                                    f'"@authority": {host.lower()}'.encode())
        assert lenient != good_base
        add(case_id, "SignatureMismatch", method="GET", body_text=None, target=query,
            headers={"Host": host,
                     "Signature-Input": "sig=" + lenient.decode().rsplit('"@signature-params": ', 1)[1],
                     "Signature": f"sig=:{base64.b64encode(key.sign(lenient)).decode()}:"},
            note="Host is the authority of an origin-form request and passes the same checks "
                 "as an absolute URL's authority. The signature is good over the base a port "
                 "that took Host verbatim would build.")
    # Lowercasing before the ASCII check reads U+212A KELVIN SIGN as "k" (review A6, B5), so a
    # non-ASCII host is refused as written, in an absolute URL as in Host. Signed over the base a
    # port that lowercased first would build.
    kelvin_base = signature_base(method="GET", url="https://api.example.com" + query, headers={},
                                 covered=DEFAULT_COVERED, created=1700000000,
                                 keyid=keyid_of(key), alg="ed25519")
    kelvin_base = kelvin_base.replace(b'"@authority": api.example.com',
                                      b'"@authority": api.example.kom')
    kelvin_signed = {
        "Signature-Input": "sig=" + kelvin_base.decode().rsplit('"@signature-params": ', 1)[1],
        "Signature": f"sig=:{base64.b64encode(key.sign(kelvin_base)).decode()}:",
    }
    add("absolute-url-host-with-a-kelvin-sign", "SignatureMismatch", method="GET",
        body_text=None, target="https://api.example.\u212aom" + query, headers=kelvin_signed,
        note="U+212A lowercases to an ASCII k. A host is checked as written, before it is "
             "lowercased; the signature is good over the base a port that lowercased first "
             "would build.")
    add("host-header-with-a-kelvin-sign", "SignatureMismatch", method="GET", body_text=None,
        target=query, headers={**kelvin_signed, "Host": "api.example.\u212aom"})
    add("host-keeps-its-default-port", "SignatureMismatch", method="GET", body_text=None,
        target=query, headers={**get_default, "Host": "api.example.com:443"},
        note="With no scheme no port is a default port, so this @authority is "
             "api.example.com:443 and the signature, over api.example.com, does not verify.")
    add("origin-form-without-host", "MissingComponent", method="GET", body_text=None,
        target=query, headers=get_default,
        note="Nothing to derive @authority from. A port that falls back to an empty or a "
             "default host lets a signature over that host verify wherever Host is stripped.")
    for case_id, target in [
        ("origin-form-target-with-a-fragment", query + "#frag"),
        ("absolute-target-with-a-fragment", "https://api.example.com" + query + "#frag"),
        ("target-with-a-del", "/thi\x7fngs?limit=1&sort=name"),
        ("target-with-a-nul", "/thi\x00ngs?limit=1&sort=name"),
    ]:
        add(case_id, "SignatureMismatch", method="GET", body_text=None, target=target,
            headers={**get_default, "Host": "api.example.com"},
            note="A request target has no fragment and no control character (RFC 9112 "
                 "section 3.2), so no base can be built.")

    for case_id, extra in [
        ("body-announced-by-transfer-encoding-only", {"Transfer-Encoding": "chunked"}),
        ("content-length-that-is-not-a-number", {"Content-Length": "abc"}),
        ("content-length-that-is-a-list", {"Content-Length": "18, 18"}),
    ]:
        add(case_id, "InsufficientCoverage", method="GET", body_text=None,
            headers={**get_default, **extra},
            note="Any transfer coding, or a length that is not a plain decimal, is evidence of a "
                 "body, so the default minimum requires a covered content-digest (profile body "
                 "test). Reading it as no body fails open.")
    add("list-minimum-is-enforced", "InsufficientCoverage", method="GET", body_text=None,
        headers=get_default, minimum=["@method", "@authority", "@path", "@query", "x-tenant"],
        note="A caller's own minimum is applied, not ignored in favour of the default.")
    add("default-minimum-without-path", "InsufficientCoverage", method="GET", body_text=None,
        headers=signed(method="GET", body=None, covered=["@method", "@authority", "@query"]))
    short = signed(method="GET", body=None, covered=["@method", "@authority", "@path"])
    add("coverage-is-checked-before-the-clock", "InsufficientCoverage", method="GET",
        body_text=None, headers=short, max_age=10, now=1700001000,
        note="Profile section 9's order. A default minimum done as a check of the verdict "
             "after verifying would say SignatureTooOld here.")
    short_bad_key = dict(short)
    real_keyid = short["Signature-Input"].split('keyid="')[1].split('"')[0]
    short_bad_key["Signature-Input"] = short["Signature-Input"].replace(real_keyid, "not-a-key")
    add("coverage-is-checked-before-the-key", "InsufficientCoverage", method="GET",
        body_text=None, headers=short_bad_key,
        note="A signature policy already refuses never reaches a key lookup, which with a "
             "resolver may be a network fetch.")
    add("authorities-are-checked-before-the-clock", "SignatureMismatch", method="GET",
        body_text=None, headers=get_default, authorities=["other.example"], max_age=10,
        now=1700001000)
    no_keyid = signed(method="GET", body=None)
    no_keyid["Signature-Input"] = no_keyid["Signature-Input"].split(";keyid=")[0] + ';alg="ed25519"'
    add("keyid-required-beside-expected-aid-under-the-default", "MissingKey", method="GET",
        body_text=None, headers=no_keyid, expected_aid=key.aid,
        note="Any minimum requires keyid even when the verifier names the key (@7y9lfnzq).")
    stranger = Key.from_seed(SEED_B)
    add("expected-aid-of-another-key", "SignatureMismatch", method="GET", body_text=None,
        headers=sign_request(key=stranger, method="GET", url=url, created=1700000000),
        expected_aid=key.aid,
        note="A stranger's valid signature, checked against the key the verifier expected "
             "(review V-C2: no vector exercised expected_aid).")

    for case_id, mangle in [
        ("tag-with-a-tab", lambda v: v + ';tag="o\tk"'),
        ("nonce-with-non-ascii", lambda v: v + ';nonce="n\u00e91"'),
        ("alg-with-a-carriage-return", lambda v: v.replace('alg="ed25519"', 'alg="ed\r25519"')),
        ("component-name-with-a-tab", lambda v: v.replace('"@path"', '"@pa\tth"')),
        ("keyid-with-an-unknown-escape", lambda v: v.replace('keyid="', 'keyid="\\q', 1)),
        ("keyid-ending-in-a-lone-backslash",
         lambda v: v.split(';keyid="')[0] + ';keyid="abc\\'),
    ]:
        bad = signed(method="GET", body=None)
        before = bad["Signature-Input"]
        bad["Signature-Input"] = mangle(before)
        assert bad["Signature-Input"] != before, case_id
        add(case_id, "MalformedSignatureInput", method="GET", headers=bad, body_text=None,
            note="Every sf-string, not only keyid, is printable ASCII, and its only escapes "
                 "are a backslash before a quote or a backslash (RFC 8941 section 3.3.3).")

    # The cofactorless Ed25519 equation (@524c8qgv), checked by RFC 8032's own code.
    for case_id, signature_text, keyid_text, note in mixed_order_refusals():
        crafted = signed(method="GET", body=None, keyid=keyid_text)
        base = signature_base(method="GET", url=url, headers={}, covered=DEFAULT_COVERED,
                              created=1700000000, keyid=keyid_text, alg="ed25519")
        add(case_id, "SignatureMismatch", method="GET", body_text=None,
            headers={**crafted, "Signature": f"sig=:{signature_text(base)}:"}, note=note)

    # --- format 3, part two (@524c8qgv's later children) ---
    by_hand = by_hand_signer(key)

    # Small-order and non-canonical keys that forge under OpenSSL (review V-C1). Each signature
    # is R = identity, S = 0, with a nonce searched for until OpenSSL's own Ed25519 verify
    # accepts it under that key, so a port on a cofactorless library without the small-order
    # refusal accepts a forgery here.
    for case_id, keyid_text in [
        ("small-order-raw-keyid-identity-with-the-sign-bit-set", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA"),
        ("small-order-raw-keyid-identity-spelled-y-equals-p-plus-1", "7v_______________________________________38"),
        ("small-order-raw-keyid-order-2-point", "7P_______________________________________38"),
        ("small-order-raw-keyid-order-2-point-with-the-sign-bit-set", "7P________________________________________8"),
        ("small-order-raw-keyid-order-4-point-with-the-sign-bit-set", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA"),
        ("small-order-raw-keyid-order-8-point", "JuiVj8KyJ7BFw_SJ8u-Y8NXfrAXTxjM5sTgCiG1T_AU"),
        ("small-order-raw-keyid-order-8-point-other", "xxdqcD1N2E-6PAt2DRBnDyogU_osOczGTsf9d5KsA3o"),
    ]:
        raw = base64.urlsafe_b64decode(keyid_text + "=")
        forgery = b"\x01" + bytes(63)
        for n in range(200):
            base = signature_base(method="GET", url=url, headers={}, covered=DEFAULT_COVERED,
                                  created=1700000000, keyid=keyid_text, alg="ed25519", nonce=f"n{n}")
            if _openssl_accepts(raw, base, forgery):
                break
        else:
            raise AssertionError(f"{case_id}: no nonce under which OpenSSL accepts the forgery")
        add(case_id, "MalformedKey", method="GET", body_text=None, headers={
            "Signature-Input": "sig=" + base.decode().rsplit('"@signature-params": ', 1)[1],
            "Signature": f"sig=:{base64.b64encode(forgery).decode()}:"},
            note=f"A forgery OpenSSL accepts: R = identity, S = 0, nonce n{n}. Refused before the "
                 "signature is examined (@37wdchu5; review V-C1).")

    real = keyid_of(key)
    for case_id, alias in [
        ("raw-keyid-with-a-non-zero-trailing-bit", real[:-1] + B64URL[B64URL.index(real[-1]) | 1]),
        ("raw-keyid-with-padding", real + "="),
        ("raw-keyid-in-the-standard-alphabet", real.replace("_", "/").replace("-", "+")),
    ]:
        assert alias != real, case_id
        add(case_id, "MalformedKey", method="GET", body_text=None,
            headers=by_hand(url, keyid=alias),
            note="Decodes to the same key under a lenient decoder; only the canonical spelling is "
                 "a key, or anything keyed on verdict.keyid is bypassed by re-spelling (V-S3).")

    add("max-age-with-no-created", "SignatureTooOld", method="GET", body_text=None, minimum=None,
        headers=by_hand(url, created=None), max_age=300, now=1701000000,
        note="Under the explicit opt-out, created is optional, and an age that cannot be computed "
             "is not within any limit (V-S1).")
    add("far-expires-does-not-replace-max-age", "SignatureTooOld", method="GET", body_text=None,
        headers=signed(method="GET", body=None, expires=1701000000), max_age=300, now=1700000400,
        note="The signer's expires is a ceiling, not the verifier's window (@67shl6c5; V-S2).")
    zeros = {**signed(method="GET", body=None), "Signature": f"sig=:{base64.b64encode(bytes(64)).decode()}:"}
    add("forged-and-stale-is-a-mismatch", "SignatureMismatch", method="GET", body_text=None,
        headers=zeros, max_age=300, now=1701000000,
        note="Freshness runs after the signature (profile section 9), so an unauthenticated "
             "message never learns the verifier's clock policy (V-M4).")
    long_sig = signed(method="GET", body=None)
    value = base64.b64decode(long_sig["Signature"].split("=:", 1)[1].rstrip(":")) + b"\x00"
    add("signature-of-sixty-five-bytes", "MalformedSignatureValue", method="GET", body_text=None,
        headers={**long_sig, "Signature": f"sig=:{base64.b64encode(value).decode()}:"},
        note="A valid signature and one byte more; truncating to 64 would verify it (V-M3).")
    for case_id, value in [("created-that-is-negative", "created=-1"),
                           ("expires-that-is-negative", "created=1700000000;expires=-1")]:
        add(case_id, "MalformedSignatureInput", method="GET", body_text=None,
            headers=by_hand(url, params_override=value),
            note="created and expires are non-negative, refused before the signature is examined.")
    add("algorithm-in-uppercase", "UnsupportedAlgorithm", method="GET", body_text=None,
        headers=by_hand(url, alg="ED25519"), note="An algorithm name is case-sensitive (V-M3).")
    add("empty-keyid", "MissingKey", method="GET", body_text=None, headers=by_hand(url, keyid=""),
        note="An empty keyid names no key (V-M5).")
    ws = signed(method="GET", body=None)
    add("signature-header-of-spaces", "MalformedSignature", method="GET", body_text=None,
        headers={**ws, "Signature": "   "},
        note="Present but empty after OWS: malformed, as every port must say alike (review B7).")
    two = signed(method="GET", body=None)
    sig_value = two["Signature"].split("=", 1)[1]
    add("two-members-in-signature-one-in-signature-input", "MalformedSignatureLabel",
        method="GET", body_text=None,
        headers={**two, "Signature": f"{two['Signature']}, other={sig_value}"},
        note="The label count is checked in both headers, not only Signature-Input (V-M3).")
    good_member = two["Signature-Input"]
    add("duplicate-label-in-signature-input-junk-last", "MissingKey", method="GET", body_text=None,
        headers={**two, "Signature-Input": f'{good_member}, sig=("@method");created=1700000000'},
        note="RFC 8941 section 4.2.2: a repeated dictionary key keeps its last value, here one "
             "without a keyid (V-M2).")
    add("duplicate-digest-member-bad-last", "DigestMismatch",
        headers=digest_signed_twice(key, url, good_first=True),
        note="The last sha-256 member wins, and it does not match the body (V-M2).")

    add("userinfo-in-an-absolute-url", "SignatureMismatch", method="GET", body_text=None,
        target="https://user@api.example.com/things?limit=1&sort=name", headers=get_default,
        note="RFC 9110 section 4.2.4: a recipient should treat userinfo as an error, since it "
             "is used to obscure the authority. A port that strips it verifies this.")
    kelvin_name = by_hand(url, extra_covered=["key-id"], headers={"key-id": "v"})
    add("field-name-with-a-kelvin-sign-is-not-the-covered-name", "MissingComponent", method="GET",
        body_text=None, headers={**{k: v for k, v in kelvin_name.items() if k != "key-id"},
                                 "\u212aey-Id": "v"},
        note="Field names fold A-Z to a-z and nothing else, so U+212A never becomes the k of a "
             "covered name (review A6, B5).")
    # Each is signed over the base a port without the bound would build, so only the bound can
    # refuse it: a twin one byte shorter is signed, then its base is lengthened by one byte.
    def lengthened(target_url, headers, old, new):
        twin = signature_base(method="GET", url=target_url, headers=headers,
                              covered=list(DEFAULT_COVERED) + [h.lower() for h in headers
                                                               if h.lower() != "host"],
                              created=1700000000, keyid=keyid_of(key), alg="ed25519")
        grown = twin.replace(old, new, 1)
        assert grown != twin and len(grown) == len(twin) + 1
        return {**headers,
                "Signature-Input": "sig=" + grown.decode().rsplit('"@signature-params": ', 1)[1],
                "Signature": f"sig=:{base64.b64encode(key.sign(grown)).decode()}:"}

    at_bound = padded_url(MAX_FIELD_BYTES)
    path = at_bound[len("https://api.example.com"):]
    add("url-over-8192-bytes", "SignatureMismatch", method="GET", body_text=None,
        target=padded_url(MAX_FIELD_BYTES + 1),
        headers=lengthened(at_bound, {}, f'"@path": {path}'.encode(), f'"@path": {path}p'.encode()),
        note="Every untrusted value is bounded before it is read. The signature is good over the "
             "base a port without the bound would build.")
    value = "N" * MAX_FIELD_BYTES
    add("covered-field-over-8192-bytes", "SignatureMismatch", method="GET", body_text=None,
        headers={**lengthened(url, {"X-Note": value}, f'"x-note": {value}'.encode(),
                              f'"x-note": {value}N'.encode()), "X-Note": value + "N"},
        note="A covered field value over the bound is a base that cannot be built.")
    host = "h" * (MAX_FIELD_BYTES - len(".example")) + ".example"
    add("host-over-8192-bytes", "SignatureMismatch", method="GET", body_text=None, target=query,
        headers={**lengthened(query, {"Host": host}, f'"@authority": {host}'.encode(),
                              f'"@authority": h{host}'.encode()), "Host": "h" + host},
        note="Host, when it supplies @authority, is a covered value and bounded like one.")

    honest = signed(method="GET", body=None)
    raw_sig = base64.b64decode(honest["Signature"].split("=:", 1)[1].rstrip(":"))
    s_plus_l = raw_sig[:32] + int.to_bytes(int.from_bytes(raw_sig[32:], "little") + rfc8032.q,
                                           32, "little")
    add("signature-whose-s-is-not-below-l", "SignatureMismatch", method="GET", body_text=None,
        headers={**honest, "Signature": f"sig=:{base64.b64encode(s_plus_l).decode()}:"},
        note="S + L satisfies the group equation, so only RFC 8032 section 5.1.7's S < L check "
             "refuses it; without it every signature has a second spelling.")
    add("non-canonical-identity-r", "SignatureMismatch", method="GET", body_text=None,
        headers={**honest, "Signature": f"sig=:{non_canonical_r_signature(url)}:"},
        note="R encoded as y = p + 1, the identity's non-canonical spelling. RFC 8032 decoding "
             "refuses it; a ZIP-215-mode verifier would not.")

    return {
        **HEADER,
        "about": "Requests every implementation must REFUSE, and the error each refusal carries.",
        "cases": cases,
    }


def accepts():
    """Complete signed requests every implementation must ACCEPT, and the verdict each yields.

    The gap this closes: signature-base.json pins what a signer produces and refusals.json pins
    what a verifier rejects, and between them nothing said that a well-formed request VERIFIES.
    A port could have passed every vector while its verify path returned the wrong AID, reported
    the wrong covered set, or refused everything. With five implementations that is not a
    theoretical hole.
    """
    key = Key.from_seed(SEED_A)
    signed_at = 1700000000
    body = b'{"hello": "world"}'
    cases = []

    def add(case_id, *, method, url, headers=None, body_text=None, covered=None, expires=None,
            max_age=None, now=None, note=None, nonce=None, after=None, minimum="default",
            authorities=None, signer=key, verify_url=None, presigned=None, received_body=None,
            expected_aid=None, tag=None):
        payload = None if body_text is None else body_text.encode("utf-8")
        sent = dict(headers or {})
        if presigned is not None:
            sent.update(presigned)
        else:
            sent.update(
                sign_request(
                    key=signer, method=method, url=url, headers=dict(sent), body=payload,
                    covered=covered, created=signed_at, expires=expires, nonce=nonce, tag=tag,
                )
            )
        if after is not None:
            after(sent)
        # The verdict is what the signer put there, read back from the signed headers, never
        # what fiki-py's verifier answers: a vector produced by the code under test pins its bugs.
        inner = http_sfv.Dictionary()
        signature_input = next(v for k, v in sent.items() if k.lower() == "signature-input")
        inner.parse(signature_input.encode("ascii"))
        member = inner["sig"]
        keyid = member.params["keyid"]
        case = {
            "id": case_id,
            "method": method,
            "url": url if verify_url is None else verify_url,
            "headers": sent,
            "body": body_text if received_body is None else received_body,
            "max_age": max_age,
            "now": signed_at if now is None else now,
            "minimum": minimum,
            "authorities": authorities,
            "expected_aid": expected_aid,
            "aid": aid_of_raw(base64.urlsafe_b64decode(keyid + "=" * (-len(keyid) % 4))),
            "keyid": keyid,
            "covered": [item.value for item in member],
        }
        if note:
            case["note"] = note
        cases.append(case)

    add("default-covered-get", method="GET", url="https://api.example.com/things?limit=1&sort=name",
        note="The shape a cron client actually sends.")
    add("post-with-a-body", method="POST", url="https://api.example.com/things", body_text=body.decode(),
        note="The digest is computed, covered, and recomputed on the way back in.")
    add("relative-url-with-host-header", method="GET", url="/things?limit=1",
        headers={"Host": "API.example.com"},
        note="What a server-side verifier holds: a request target and a header block.")
    add("no-query-at-all", method="GET", url="https://api.example.com/things",
        note="@query binds 'no query' as a bare question mark rather than going uncovered.")
    add("inside-max-age", method="GET", url="https://api.example.com/x", max_age=300,
        now=signed_at + 120, note="A freshness policy that the request satisfies.")
    add("before-its-expiry", method="GET", url="https://api.example.com/x",
        expires=signed_at + 600, max_age=None, now=signed_at + 60)
    add("chosen-covered-set", method="POST", url="https://api.example.com/x",
        body_text=body.decode(), covered=["@method", "@path", "content-digest"], minimum=None,
        note="A caller who names their own covered set, including the digest, verified by one "
             "who opts out of the default minimum (format 3); under the default it is "
             "InsufficientCoverage, for want of @authority and @query.")
    add("non-default-port", method="GET", url="https://api.example.com:8443/x")

    # --- format 2: the 0.8.0 cross-port sweep (@5zrf8gjk) ---
    add("extension-method-kept-as-sent", method="M-Search", url="https://api.example.com/x",
        note="Any RFC 9110 token is a method, and its case is the signer's.")
    add("port-with-leading-zeros", method="GET", url="https://api.example.com:000443/x",
        note=":000443 is 443, the https default.")
    add("ipv6-literal", method="GET", url="https://[2001:db8::1]:8443/x")
    add("port-of-thousands-of-leading-zeros", method="GET",
        url="https://api.example.com:" + "0" * 5000 + "443/x",
        note="Leading zeros are stripped before the port is read, so no run of them overflows "
             "or exceeds a conversion limit: this is 443, the https default.")

    def trailing_ows(sent):
        sent["Signature"] += " \t"

    add("signature-with-trailing-ows-after-its-member", method="GET",
        url="https://api.example.com/x", after=trailing_ows,
        note="RFC 8941 section 4.2.2 discards OWS after a dictionary member.")
    good = content_digest(body)
    add("sixteen-members-sixty-four-components-sixteen-parameters", method="POST",
        url="https://api.example.com/x", body_text=body.decode(),
        headers={"Content-Digest": good + "".join(f";p{i}" for i in range(16))
                 + "".join(f", x{i}=:AAAA:" for i in range(15)),
                 **{f"x-h{i}": str(i) for i in range(59)}},
        covered=["@method", "@authority", "@path", "@query", "content-digest",
                 *(f"x-h{i}" for i in range(59))],
        note="Each bound reached and none exceeded: 16 Content-Digest members, 64 covered "
             "components, 16 parameters on one item.")

    probe = sign_request(key=key, method="POST", url="https://api.example.com/x", body=body,
                         created=signed_at)
    long_nonce = "A" * (MAX_FIELD_BYTES - len(probe["Signature-Input"]) - len(';nonce=""'))

    def at_the_limit(sent):
        sent["Signature"] = padded_to(MAX_FIELD_BYTES, sent["Signature"] + ';x="', '"')
        assert len(sent["Signature-Input"]) == len(sent["Signature"]) == MAX_FIELD_BYTES
        assert len(sent["Content-Digest"]) == MAX_FIELD_BYTES

    add("fields-of-exactly-8192-bytes", method="POST", url="https://api.example.com/x",
        body_text=body.decode(), nonce=long_nonce, after=at_the_limit,
        headers={"Content-Digest": padded_to(MAX_FIELD_BYTES, f'{good}, x="', '"')},
        note="Signature-Input, Signature and Content-Digest at exactly the bound, which is "
             "read; one byte more is malformed.")

    # --- format 3 (@524c8qgv) ---
    add("uncovered-body-under-an-explicit-opt-out", method="GET",
        url="https://api.example.com/x", minimum=None, body_text=None,
        received_body=body.decode(),
        note="minimum=None is the explicit opt-out, and it still accepts what 0.8 accepted.")
    add("served-authority", method="GET", url="https://api.example.com/x",
        authorities=["api.example.com", "other.example"])
    add("origin-form-path-with-a-leading-double-slash", method="GET",
        url="https://victim.example//evil.example/p", verify_url="//evil.example/p",
        headers={"Host": "victim.example"},
        note="Signed for victim.example with the path //evil.example/p, and verified from the "
             "origin-form target and the Host header.")
    add("content-length-zero-is-no-body", method="GET", url="https://api.example.com/x",
        headers={"Content-Length": "0"},
        note="fetch and most clients send Content-Length: 0 on a bodiless request.")
    add("an-empty-body-is-no-body", method="GET", url="https://api.example.com/x",
        received_body="", note="A zero-length body, as opposed to none, needs no digest.")
    add("a-list-minimum-replaces-the-default", method="GET", url="https://api.example.com/x",
        covered=["@method", "@path", "@query"], minimum=["@method", "@path", "@query"],
        note="A caller's own minimum, here the KERI profile's, replaces the default rather than "
             "joining it, so a profile signer that omits @authority is admitted.")
    add("double-slash-target-under-served-authorities", method="GET",
        url="https://victim.example//evil.example/p?x=1", verify_url="//evil.example/p?x=1",
        headers={"Host": "victim.example"}, authorities=["victim.example"],
        note="The authority compared with authorities is Host's, not one parsed out of the path.")
    add("expected-aid-of-the-signer", method="GET", url="https://api.example.com/x",
        expected_aid=key.aid)
    good_digest = content_digest(body)
    add("dictionary-members-joined-by-comma-and-tab", method="POST",
        url="https://api.example.com/x", body_text=body.decode(),
        headers={"Content-Digest": good_digest + ",\tx=:AAAA:"},
        note="RFC 8941 section 4.2.2 allows OWS, tab included, after a dictionary's comma.")
    add("cofactorless-accept-with-torsion-in-r", method="GET", url="https://api.example.com/x",
        presigned=torsion_r_accept(signed_at),
        note="R and the key each carry a point of order 8, and they cancel, so [S]B = R + [k]A "
             "holds. A hand-written check that refuses any R outside the prime-order subgroup "
             "fails here.")
    no_created_base = signature_base(method="GET", url="https://api.example.com/x", headers={},
                                     covered=DEFAULT_COVERED, created=signed_at,
                                     keyid=keyid_of(key), alg="ed25519")
    stripped = no_created_base.replace(b";created=%d" % signed_at, b"")
    add("no-created-under-the-explicit-opt-out", method="GET", url="https://api.example.com/x",
        minimum=None, presigned={
            "Signature-Input": "sig=" + stripped.decode().rsplit('"@signature-params": ', 1)[1],
            "Signature": f"sig=:{base64.b64encode(key.sign(stripped)).decode()}:"},
        note="minimum=None drops the created requirement with the rest of the minimum.")
    # --- format 3, part two ---
    by_hand = by_hand_signer(key)
    add("created-after-2038", method="GET", url="https://api.example.com/x",
        presigned=by_hand("https://api.example.com/x", created=4102444800), max_age=300,
        now=4102444810, note="A created that does not fit in 32 bits (V-M5).")
    add("parameters-in-the-signers-order", method="GET", url="https://api.example.com/x",
        presigned=by_hand("https://api.example.com/x", order=("keyid", "alg", "created")),
        note="RFC 9421 section 2.3: once a parameter order is chosen it cannot be changed; a "
             "verifier that re-emits its own order fails this (V-S4).")
    spaced = by_hand("https://api.example.com/x")
    spaced["Signature-Input"] = spaced["Signature-Input"].replace(
        '("@method" "@authority" "@path" "@query")', '(  "@method"   "@authority"   "@path"   "@query")')
    assert "(  " in spaced["Signature-Input"]
    add("signature-input-with-extra-spaces-in-its-inner-list", method="GET",
        url="https://api.example.com/x", presigned=spaced,
        note="@signature-params is the serialization of the parsed list, not the header's text.")
    add("lowercase-field-names", method="POST", url="https://api.example.com/x",
        body_text=body.decode(), after=lambda sent: sent.update(
            {name.lower(): sent.pop(name) for name in list(sent)}),
        note="Field names match case-insensitively; Node and HTTP/2 hand them over lowercase.")
    add("tag-is-signed-like-nonce", method="GET", url="https://api.example.com/x", tag="app-1")
    add("http-default-port-80-is-dropped", method="GET", url="http://api.example.com/x",
        verify_url="http://api.example.com:80/x")
    add("scheme-in-uppercase", method="GET", url="https://api.example.com/x",
        verify_url="HTTPS://api.example.com/x")
    add("empty-path-is-a-slash", method="GET", url="https://api.example.com",
        verify_url="https://api.example.com/")
    add("sha-512-only-digest", method="POST", url="https://api.example.com/x",
        body_text=body.decode(), headers={"Content-Digest": sha512_digest(body)},
        note="RFC 9530 sha-512 alone is a digest fiki computes.")
    add("duplicate-digest-member-good-last", method="POST", url="https://api.example.com/x",
        presigned=digest_signed_twice(key, "https://api.example.com/x", good_first=False),
        body_text=body.decode(), note="The last sha-256 member wins (V-M2).")
    add("url-of-exactly-8192-bytes", method="GET", url=padded_url(MAX_FIELD_BYTES))
    for case_id, signer_seed, crafted_headers, note in mixed_order_accepts(signed_at):
        add(case_id, method="GET", url="https://api.example.com/x", presigned=crafted_headers,
            note=note)

    return {**HEADER,
            "about": "Complete signed requests every implementation must ACCEPT, and the verdict.",
            "cases": cases}


def signs():
    """What each signer emits, byte for byte (review V-C4).

    Before this, no shared vector called a signer, so a port whose default covered set dropped
    @query, or which signed a body it did not digest, passed every vector. Ed25519 is
    deterministic, so every header a signer returns is compared exactly. These are fiki-py's
    output; the anchor against that being circular is signature-base.json's RFC 9421 B.2.6 case,
    which pins base construction and the signature over it from text no Bakobo party wrote.
    """
    cases = []
    body = '{"hello": "world"}'

    def add(case_id, *, kind="request", method="GET", url="https://api.example.com/things?limit=1",
            headers=None, body_text=None, covered=None, created=1700000000, expires=None,
            nonce=None, tag=None, minimum=None, status=None, request=None, error=None, note=None):
        key = Key.from_seed(SEED_A)
        case = {"id": case_id, "kind": kind, "seed_hex": SEED_A.hex(), "method": method,
                "url": url, "headers": headers or {}, "body": body_text, "covered": covered,
                "created": created, "expires": expires, "nonce": nonce, "tag": tag,
                "minimum": minimum, "status": status, "request": request}
        payload = None if body_text is None else body_text.encode()
        args = dict(key=key, headers=dict(headers or {}), body=payload, covered=covered,
                    created=created, expires=expires, nonce=nonce, tag=tag, minimum=minimum)
        try:
            if kind == "request":
                out = sign_request(method=method, url=url, **args)
            else:
                out = sign_response(status=status, request=Request(**{
                    **request, "body": None if request["body"] is None else request["body"].encode()}),
                    **args)
        except Exception as ex:  # noqa: BLE001 - the case records which refusal it is
            assert error is not None, f"{case_id}: fiki-py refused unexpectedly: {ex!r}"
            case["error"] = type(ex).__name__ if type(ex).__module__.startswith("fiki") else "caller"
            assert case["error"] == error, f"{case_id}: {case['error']} != {error}"
        else:
            assert error is None, f"{case_id}: fiki-py signed what it should refuse"
            case["expected_headers"] = out
        if note:
            case["note"] = note
        cases.append(case)

    add("default-covered-get", note="The default covered set: method, authority, path, query.")
    add("default-covered-post-with-a-body", method="POST", body_text=body,
        note="A body adds a Content-Digest, computed and covered.")
    add("chosen-covered-set-with-the-digest", method="POST", body_text=body,
        covered=["@method", "@path", "content-digest"])
    add("chosen-covered-set-omitting-the-digest-of-a-body", method="POST", body_text=body,
        covered=["@method", "@authority", "@path", "@query"], error="UncoveredBody",
        note="A body nothing digests is refused, with no minimum (README's guarantee).")
    add("caller-supplied-digest-is-used", method="POST", body_text=body,
        headers={"Content-Digest": content_digest(body.encode())})
    add("expires-nonce-and-tag", expires=1700000600, nonce="n-1", tag="app-1",
        note="Parameters in fiki's emission order: created, expires, nonce, alg, keyid, tag.")
    add("relative-url-with-host", url="/things?limit=1", headers={"Host": "api.example.com"})
    request = {"method": "POST", "url": "https://api.example.com/things",
               "headers": {"Content-Digest": content_digest(body.encode())}, "body": body}
    add("response-default-covered", kind="response", status=200, body_text='{"done": true}',
        method=None, url=None, request=request,
        note="A response binds @status, its body, and the request's method, path, query and "
             "digest, each marked req.")
    return {**HEADER, "about": "What every implementation's signer must emit, byte for byte.",
            "cases": cases}


def responses():
    """verify_response's own policy (@524c8qgv, 'verify_response applies RESPONSE_MINIMUM')."""
    key, stranger = Key.from_seed(SEED_A), Key.from_seed(SEED_B)
    url = "https://api.example.com/things?limit=1"
    request = {"method": "GET", "url": url, "headers": {}, "body": None}
    as_request = Request(method="GET", url=url, headers={}, body=None)
    cases = []

    def add(case_id, *, signer=key, covered=None, minimum="default", expected_keyid=None,
            status=200, body='{"done": true}', request=request, error=None, note=None,
            mangle=None, max_age=None, now=1700000000):
        payload = None if body is None else body.encode()
        headers = sign_response(key=signer, status=status, request=as_request, body=payload,
                                covered=covered, created=1700000000)
        if mangle:
            headers = mangle(headers)
        case = {"id": case_id, "status": status, "headers": headers, "body": body,
                "request": request, "minimum": minimum, "expected_keyid": expected_keyid,
                "max_age": max_age, "now": now}
        if error:
            case["error"] = error
        else:
            case.update(keyid=keyid_of(signer), covered=list(covered or [
                "@status", '"@method";req', '"@path";req', '"@query";req', "content-digest"]))
        if note:
            case["note"] = note
        cases.append(case)

    mine = keyid_of(key)
    add("default-response", expected_keyid=mine)
    add("response-covering-only-status-under-the-default", covered=["@status"], body=None,
        expected_keyid=mine, error="InsufficientCoverage",
        note="The default minimum is RESPONSE_MINIMUM. Before format 3 this verified.")
    add("response-covering-only-status-under-the-opt-out", covered=["@status"], minimum=None,
        expected_keyid=mine, body=None)
    add("response-from-a-key-other-than-the-expected", signer=stranger, expected_keyid=mine,
        error="UnknownKey", note="Profile R1: a client checks the keyid is the AID it expects.")
    add("expected-keyid-declined", expected_keyid=None,
        note="An explicit decline admits any signer, and the verdict names it.")
    return {**HEADER, "about": "Responses every implementation must accept or refuse.",
            "cases": cases}


def misuse():
    """Mistakes in the call, which every port reports in its own caller-error idiom, never as a
    FikiError (@5zrf8gjk's convention). A vector cannot name six idioms, so each case says only
    "caller"; a driver maps that to its port's type and asserts the error is not a FikiError.
    Each case is a valid request with one argument wrong, so nothing else can be what refused it.
    A field listed in "omit" is left out of the call altogether.
    """
    key = Key.from_seed(SEED_A)
    url = "https://api.example.com/things?limit=1"
    base = {"method": "GET", "url": url, "body": None, "max_age": None, "now": 1700000000,
            "headers": sign_request(key=key, method="GET", url=url, created=1700000000),
            "minimum": "default", "authorities": None, "expected_aid": None, "omit": []}
    cases = []

    def add(case_id, note, **changes):
        cases.append({"id": case_id, **base, **changes, "error": "caller", "note": note})

    add("authorities-is-a-string", "A string is a collection of characters, so in would be a "
        "substring test that lets api.example.com admit example.com (review A3).",
        authorities="api.example.com")
    add("authorities-is-a-string-containing-the-host", "The A3 substring bug made concrete.",
        authorities="xapi.example.comx")
    add("authorities-is-empty", "An empty collection serves no host; None declines the check.",
        authorities=[])
    add("authorities-holds-a-non-string", "Every authority is a string.",
        authorities=["api.example.com", 443])
    add("authorities-omitted", "authorities is a required decision with no default (@524c8qgv).",
        omit=["authorities"])
    add("minimum-below-the-profiles", "A minimum must include REQUEST_MINIMUM.",
        minimum=["@method", "@query"])
    add("minimum-empty", "An empty minimum is below the profile's.", minimum=[])
    response = {**base, "kind": "response", "status": 200, "body": '{"done": true}',
                "request": {"method": "GET", "url": url, "headers": {}, "body": None},
                "headers": sign_response(key=key, status=200, created=1700000000,
                                         request=Request(method="GET", url=url, headers={}, body=None),
                                         body=b'{"done": true}'),
                "expected_keyid": keyid_of(key)}
    for field in ("authorities", "expected_aid"):
        response.pop(field)
    cases.append({**response, "id": "response-expected-keyid-omitted", "omit": ["expected_keyid"],
                  "error": "caller", "note": "expected_keyid is a required decision (@524c8qgv)."})
    cases.append({**response, "id": "response-minimum-below-the-profiles", "minimum": ["@status"],
                  "error": "caller", "note": "A response minimum must include RESPONSE_MINIMUM."})
    return {**HEADER, "about": "Calls every implementation must reject as a caller's mistake.",
            "cases": cases}


def main() -> None:
    out = Path(__file__).resolve().parent
    for name, data in [
        ("aid-lens.json", aid_lens()),
        ("signature-base.json", signature_bases()),
        ("accepts.json", accepts()),
        ("refusals.json", refusals()),
        ("misuse.json", misuse()),
        ("signs.json", signs()),
        ("responses.json", responses()),
    ]:
        (out / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {name}: {len(data['cases'])} cases")


if __name__ == "__main__":
    main()

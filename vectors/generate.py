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
    Key,
    sign_request,
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
            note=None, max_age=None, now=None, minimum="default", authorities=None):
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

    # The cofactorless Ed25519 equation (@524c8qgv), checked by RFC 8032's own code.
    for case_id, signature_text, keyid_text, note in mixed_order_refusals():
        crafted = signed(method="GET", body=None, keyid=keyid_text)
        base = signature_base(method="GET", url=url, headers={}, covered=DEFAULT_COVERED,
                              created=1700000000, keyid=keyid_text, alg="ed25519")
        add(case_id, "SignatureMismatch", method="GET", body_text=None,
            headers={**crafted, "Signature": f"sig=:{signature_text(base)}:"}, note=note)

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
            authorities=None, signer=key, verify_url=None, presigned=None, received_body=None):
        payload = None if body_text is None else body_text.encode("utf-8")
        sent = dict(headers or {})
        if presigned is not None:
            sent.update(presigned)
        else:
            sent.update(
                sign_request(
                    key=signer, method=method, url=url, headers=dict(sent), body=payload,
                    covered=covered, created=signed_at, expires=expires, nonce=nonce,
                )
            )
        if after is not None:
            after(sent)
        # The verdict is what the signer put there, read back from the signed headers, never
        # what fiki-py's verifier answers: a vector produced by the code under test pins its bugs.
        inner = http_sfv.Dictionary()
        inner.parse(sent["Signature-Input"].encode("ascii"))
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
    for case_id, signer_seed, crafted_headers, note in mixed_order_accepts(signed_at):
        add(case_id, method="GET", url="https://api.example.com/x", presigned=crafted_headers,
            note=note)

    return {**HEADER,
            "about": "Complete signed requests every implementation must ACCEPT, and the verdict.",
            "cases": cases}


def main() -> None:
    out = Path(__file__).resolve().parent
    for name, data in [
        ("aid-lens.json", aid_lens()),
        ("signature-base.json", signature_bases()),
        ("accepts.json", accepts()),
        ("refusals.json", refusals()),
    ]:
        (out / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {name}: {len(data['cases'])} cases")


if __name__ == "__main__":
    main()

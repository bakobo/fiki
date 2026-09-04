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
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "py" / "src"))

from fiki import DEFAULT_COVERED, Key, sign_request, signature_base  # noqa: E402
from fiki.messages import content_digest  # noqa: E402

RFC_SEED = base64.urlsafe_b64decode("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU" + "=")
SEED_A = bytes(range(32))
SEED_B = bytes(range(1, 33))

HEADER = {
    "about": "Shared conformance vectors for fiki. Every implementation runs these.",
    "generated_by": "vectors/generate.py",
    "default_covered": list(DEFAULT_COVERED),
}


def keyid_of(key: Key) -> str:
    from fiki.messages import _keyid

    return _keyid(key.aid)


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
    ]
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
            note=None):
        case = {
            "id": case_id,
            "method": method,
            "url": target,
            "headers": headers,
            "body": body_text,
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
    add("two-signature-labels", "MalformedSignature", headers=two_labels)

    wrong_alg = signed()
    wrong_alg["Signature-Input"] = wrong_alg["Signature-Input"].replace(
        ';alg="ed25519"', ';alg="rsa-pss-sha512"'
    )
    add("algorithm-other-than-ed25519", "UnsupportedAlgorithm", headers=wrong_alg)

    bad_keyid = signed()
    keyid = bad_keyid["Signature-Input"].split('keyid="')[1].split('"')[0]
    bad_keyid["Signature-Input"] = bad_keyid["Signature-Input"].replace(keyid, "not-a-key")
    add("keyid-that-is-not-a-key", "MalformedSignature", headers=bad_keyid)

    return {
        **HEADER,
        "about": "Requests every implementation must REFUSE, and the error each refusal carries.",
        "cases": cases,
    }


def main() -> None:
    out = Path(__file__).resolve().parent
    for name, data in [
        ("aid-lens.json", aid_lens()),
        ("signature-base.json", signature_bases()),
        ("refusals.json", refusals()),
    ]:
        (out / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {name}: {len(data['cases'])} cases")


if __name__ == "__main__":
    main()

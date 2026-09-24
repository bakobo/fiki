"""fiki-py runs the KERI profile's vector set, ``vectors/keri/`` (``this.i`` @8vwrexxc).

A separate contract from the shared ``vectors/``: its own format number, refusals named by the
profile's neutral section 9 codes rather than fiki's class names, and — for now — only this port
runs it. signify-ts and keripy load the same JSON directly, so everything this driver needs is in
the files; the only thing it adds is the resolver a KERI verifier would back with key event logs,
built here from the keys table each file carries.

The resolver is authoritative (@6g9zjsv9). It derives a non-transferable ``B…`` keyid from the
prefix, looks every transferable keyid up in the table, answers None for a well-formed AID it has
no key state for, and refuses a keyid that is not an AID at all. It never decodes a ``D…`` keyid
as a key, which is exactly what one of the vectors is there to catch.
"""

from __future__ import annotations

import base64
import binascii
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fiki import (
    Key,
    Request,
    response_signature_base,
    sign_request,
    signature_base,
    verify_request,
    verify_response,
    verifying_key,
)
from fiki.base import component
from fiki.errors import FikiError, MalformedKey

KERI = Path(__file__).resolve().parents[2] / "vectors" / "keri"
FILES = ("rfc9421.json", "requests.json", "responses.json", "refusals.json", "legacy.json")

# The format this port satisfies. A separate number from fiki.VECTORS_FORMAT, because the two sets
# answer to different authorities and move independently (@8vwrexxc).
KERI_VECTORS_FORMAT = 1


def _generator():
    spec = importlib.util.spec_from_file_location("keri_generate", KERI / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CODES = _generator().CODES


def load(name: str) -> dict:
    return json.loads((KERI / name).read_text(encoding="utf-8"))


def cases(name: str):
    return [pytest.param(case, id=case["id"]) for case in load(name)["cases"]]


def b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def resolver(keys: list[dict]):
    table = {entry["keyid"]: b64url(entry["public_key"]) for entry in keys
             if entry["kind"] == "transferable"}

    def resolve(keyid: str):
        if keyid in table:
            return table[keyid]
        try:
            well_formed = len(keyid) == 44 and keyid[0] in "BDE" and len(
                base64.b64decode("A" + keyid[1:], altchars=b"-_", validate=True)) == 33
        except binascii.Error:
            well_formed = False
        if not well_formed:
            raise MalformedKey(f'"{keyid}" is not a well-formed AID.', keyid=keyid)
        if keyid.startswith("B"):
            return verifying_key(keyid).public_bytes_raw()
        return None

    return resolve


def body_of(message: dict) -> bytes | None:
    return None if message["body"] is None else message["body"].encode("utf-8")


def as_request(message: dict) -> Request:
    return Request(method=message["method"], url=message["url"], headers=message["headers"],
                   body=body_of(message))


def run(case: dict, data: dict):
    """Verify a case's message under the file's stated policy, as a KERI verifier would."""
    policy = data["policy"]
    common = dict(max_age=policy["max_age"], skew=policy["skew"], now=case["now"],
                  resolve=resolver(data["keys"]))
    if "response" in case:
        response = case["response"]
        return verify_response(
            status=response["status"], headers=response["headers"], body=body_of(response),
            request=as_request(case["request"]), minimum=policy["response_minimum"], **common,
        )
    request = case["request"]
    return verify_request(
        method=request["method"], url=request["url"], headers=request["headers"],
        body=body_of(request), minimum=policy["request_minimum"], **common,
    )


def serialized(covered) -> list[str]:
    return [str(component(spec)) for spec in covered]


# --- the files themselves ---

@pytest.mark.parametrize("name", FILES)
def test_this_port_satisfies_the_keri_vectors_format_it_is_running(name):
    """The same guard @4fhrre0m gives the shared set, against its own number."""
    data = load(name)
    assert data["keri_vectors_format"] == KERI_VECTORS_FORMAT
    assert "vectors_format" not in data
    assert data["cases"]


@pytest.mark.parametrize("name", ["requests.json", "responses.json", "refusals.json"])
def test_each_file_states_the_policy_it_assumes(name):
    policy = load(name)["policy"]
    assert policy["max_age"] == 300
    assert policy["skew"] == 60
    assert policy["request_minimum"] == ['"@method"', '"@path"', '"@query"']
    assert policy["response_minimum"] == [
        '"@status"', '"@method";req', '"@path";req', '"@query";req'
    ]


@pytest.mark.parametrize("name", ["requests.json", "responses.json", "refusals.json"])
def test_the_keys_table_agrees_with_its_seeds(name):
    """A table entry that disagrees with its own seed would make every case using it a lie."""
    for entry in load(name)["keys"]:
        key = Key.from_seed(bytes.fromhex(entry["seed_hex"]))
        assert b64url(entry["public_key"]) == verifying_key(key.aid).public_bytes_raw()
        if entry["kind"] == "non-transferable":
            assert entry["keyid"] == key.aid


def test_every_refusal_names_a_profile_code_and_every_code_fiki_can_produce_is_exercised():
    data = load("refusals.json")
    named = {case["error"] for case in data["cases"]}
    assert named <= set(data["codes"])
    assert set(CODES.values()) <= named


def test_every_fiki_error_has_a_profile_code():
    """The same totality heti's boundary test enforces (@8zw78n0v), against the profile's codes."""
    from fiki import errors

    def walk(cls):
        for sub in cls.__subclasses__():
            yield sub
            yield from walk(sub)

    concrete = {cls.__name__ for cls in walk(errors.FikiError) if not cls.__name__.startswith("_")}
    assert concrete == set(CODES)


def test_the_refusal_codes_are_neutral_rather_than_fiki_class_names():
    for case in load("refusals.json")["cases"]:
        assert case["error"] == case["error"].lower()
        assert case["error"] not in CODES


# --- RFC 9421 B.2.6, which anchors the set to something no Bakobo party wrote ---

def test_rfc_9421_b_2_6_is_the_rfcs_own_base_and_signature():
    from test_rfc9421_conformance import RFC_BASE, RFC_SIGNATURE

    (case,) = load("rfc9421.json")["cases"]
    assert case["expected"]["base"] == RFC_BASE
    assert case["expected"]["signature"] == RFC_SIGNATURE
    request = case["request"]
    base = signature_base(
        method=request["method"], url=request["url"], headers=request["headers"],
        covered=case["covered"], created=case["created"], keyid=case["keyid"],
    )
    assert base.decode("utf-8") == RFC_BASE
    signature = Key.from_seed(bytes.fromhex(case["seed_hex"])).sign(base)
    assert base64.b64encode(signature).decode("ascii") == RFC_SIGNATURE


# --- the accept cases ---

@pytest.mark.parametrize("case", cases("requests.json"))
def test_request_accept_vectors(case):
    data = load("requests.json")
    verdict = run(case, data)
    expected = case["expected"]
    assert verdict.keyid == expected["keyid"]
    assert serialized(verdict.covered) == expected["covered"]
    assert _base_of(case, data["keys"]) == expected["base"]


@pytest.mark.parametrize("case", cases("responses.json"))
def test_response_accept_vectors(case):
    data = load("responses.json")
    verify_request(
        method=case["request"]["method"], url=case["request"]["url"],
        headers=case["request"]["headers"], body=body_of(case["request"]),
        max_age=data["policy"]["max_age"], skew=data["policy"]["skew"], now=case["now"],
        resolve=resolver(data["keys"]), minimum=data["policy"]["request_minimum"],
    )
    verdict = run(case, data)
    expected = case["expected"]
    assert verdict.keyid == expected["keyid"]
    assert serialized(verdict.covered) == expected["covered"]
    assert _base_of(case, data["keys"]) == expected["base"]


def _base_of(case: dict, keys: list[dict]) -> str:
    """Rebuild the expected base from the message and its Signature-Input, then check the bytes.

    Built through fiki's own signing-side base functions from the parameters the header carries,
    so an accept vector pins the base a SIGNER produces as well as the one a verifier rebuilds.
    """
    message = case.get("response", case["request"])
    import http_sfv

    parsed = http_sfv.Dictionary()
    parsed.parse(message["headers"]["Signature-Input"].encode("utf-8"))
    (inner,) = parsed.values()
    params = dict(inner.params)
    kwargs = dict(covered=list(inner), created=params["created"], keyid=params["keyid"],
                  alg=params.get("alg"), expires=params.get("expires"),
                  nonce=params.get("nonce"), tag=params.get("tag"))
    if "response" in case:
        base = response_signature_base(status=message["status"], headers=message["headers"],
                                       request=as_request(case["request"]), **kwargs)
    else:
        base = signature_base(method=message["method"], url=message["url"],
                              headers=message["headers"], **kwargs)
    signature = message["headers"]["Signature"].split("=", 1)[1].strip(":")
    public = resolver(keys)(params["keyid"])
    Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(signature), base)
    return base.decode("utf-8")


# --- the refusals ---

@pytest.mark.parametrize("case", cases("refusals.json"))
def test_refusal_vectors(case):
    """Each case has one defect and so one correct code under the profile's section 9 order."""
    data = load("refusals.json")
    with pytest.raises(FikiError) as caught:
        if case["kind"] == "sign-request":
            request = case["request"]
            sign_request(
                key=Key.from_seed(bytes.fromhex(case["seed_hex"])), method=request["method"],
                url=request["url"], headers=request["headers"], body=body_of(request),
                covered=case["covered"], keyid=case["keyid"],
            )
        else:
            run(case, data)
    assert CODES[type(caught.value).__name__] == case["error"]


# --- legacy material, which fiki carries and never verifies ---

def test_legacy_vectors_carry_what_a_legacy_verifier_needs_and_their_provenance():
    data = load("legacy.json")
    for case in data["cases"]:
        source = case["source"]
        assert source["repo"] in {"WebOfTrust/keria", "WebOfTrust/signify-ts"}
        assert len(source["commit"]) == 40
        assert source["file"] and source["lines"]
        for field in ("kind", "method", "path", "headers", "key", "keyid", "created"):
            assert field in case, field
        assert case["headers"]["Signature-Input"].startswith("signify=")
        assert case["headers"]["Signature"].startswith('indexed="?0";signify="0B')


@pytest.mark.parametrize("case", cases("legacy.json"))
def test_each_legacy_signature_verifies_over_its_stated_base(case):
    """Transcription check only: pure Ed25519 over the base the file states, no legacy logic."""
    signature = case["headers"]["Signature"].split('signify="', 1)[1].rstrip('"')
    raw_signature = base64.urlsafe_b64decode("AA" + signature[2:])[2:]
    raw_key = base64.urlsafe_b64decode("A" + case["key"][1:])[1:]
    Ed25519PublicKey.from_public_bytes(raw_key).verify(raw_signature, case["base"].encode())

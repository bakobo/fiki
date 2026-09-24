"""fiki-py runs the KERI profile's vector set, ``vectors/keri/`` (``this.i`` @8vwrexxc).

A separate contract from the shared ``vectors/``: its own format number, refusals named by the
profile's neutral section 9 codes rather than fiki's class names, and — for now — only this port
runs it. signify-ts and keripy load the same JSON directly, so everything this driver needs is in
the files; the only thing it adds is the resolver a KERI verifier would back with key event logs,
built here from the keys table each file carries.

The resolver is authoritative (@6g9zjsv9). It derives a non-transferable ``B…`` keyid from the
prefix, looks every transferable keyid up in the table, answers None for a well-formed AID it has
no key state for, raises UnsupportedSigner for a key state with no single effective signer, and
refuses a keyid that is not an AID at all. It never decodes a ``D…`` keyid as a key, which is
exactly what one of the vectors is there to catch. The resolver, the well-formedness rule and the
policy-applying verifier are the generator's own, imported rather than copied, so the rule the
files state is the one this driver runs (@4tkkp50h).
"""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fiki import Key, sign_request, signature_base, verifying_key
from fiki.base import component
from fiki.errors import FikiError

KERI = Path(__file__).resolve().parents[2] / "vectors" / "keri"
FILES = ("rfc9421.json", "requests.json", "responses.json", "refusals.json", "legacy.json")

# The format this port satisfies. A separate number from fiki.VECTORS_FORMAT, because the two sets
# answer to different authorities and move independently (@8vwrexxc).
KERI_VECTORS_FORMAT = 2


def _generator():
    spec = importlib.util.spec_from_file_location("keri_generate", KERI / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR = _generator()
CODES = GENERATOR.CODES


def load(name: str) -> dict:
    return json.loads((KERI / name).read_text(encoding="utf-8"))


def cases(name: str):
    return [pytest.param(case, id=case["id"]) for case in load(name)["cases"]]


def b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def body_of(message: dict) -> bytes | None:
    return None if message["body"] is None else message["body"].encode("utf-8")


def run(case: dict, data: dict):
    """Verify a case's message under the file's policy extended by the case's, as a KERI verifier."""
    policy = {**data["policy"], **case.get("policy", {})}
    return GENERATOR.verify(case["request"], case.get("response"), now=case["now"],
                            policy=policy, keys=data["keys"])


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


@pytest.mark.parametrize("name", FILES)
def test_each_file_names_the_published_profile_it_pins(name):
    """The contract is a document anyone can read, beside these files (@997vxdu7)."""
    profile = load(name)["profile"]
    assert profile["version"] == 1
    assert profile["where"] == "https://github.com/bakobo/fiki/blob/main/docs/keri-profile.md"
    doc = KERI.parents[1] / "docs" / "keri-profile.md"
    assert doc.read_text(encoding="utf-8").startswith(f"# {profile['title']}\n\nVersion 1, ")


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
def test_the_keys_table_agrees_with_its_seeds_and_key_states(name):
    """A table entry that disagrees with its own seed would make every case using it a lie."""
    data = load(name)
    assert data["keys_rule"]
    for entry in data["keys"]:
        assert GENERATOR.well_formed_aid(entry["keyid"])
        signer = verifying_key(Key.from_seed(bytes.fromhex(entry["seed_hex"])).aid)
        if entry["kind"] == "non-transferable":
            assert entry["keyid"] == Key.from_seed(bytes.fromhex(entry["seed_hex"])).aid
            continue
        state = [base64.urlsafe_b64decode("A" + key[1:])[1:] for key in entry["key_state"]["keys"]]
        assert all(key.startswith("D") and len(key) == 44 for key in entry["key_state"]["keys"])
        if entry["effective_key"] is None:
            assert signer.public_bytes_raw() == state[0]
        else:
            assert b64url(entry["effective_key"]) == signer.public_bytes_raw()
            assert signer.public_bytes_raw() in state


def test_the_well_formedness_rule_refuses_near_misses():
    assert not GENERATOR.well_formed_aid("E" + "!" * 43)
    assert not GENERATOR.well_formed_aid("A" + "A" * 43)
    assert not GENERATOR.well_formed_aid("not-an-aid")


@pytest.mark.parametrize("name", ["requests.json"])
def test_the_well_formedness_rule_refuses_a_padding_bit_alias(name):
    """bakobo/fiki#4: a B keyid spelled with a non-zero pad bit would alias the same key."""
    from test_keys import padding_bit_alias

    for entry in load(name)["keys"]:
        alias = padding_bit_alias(entry["keyid"])
        assert GENERATOR.well_formed_aid(entry["keyid"])
        assert not GENERATOR.well_formed_aid(alias)


def test_every_refusal_names_a_profile_code_and_every_profile_code_is_exercised():
    data = load("refusals.json")
    named = {case["error"] for case in data["cases"]}
    assert named == set(data["codes"])
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
    assert GENERATOR.expected_base(case["request"], keys=data["keys"]) == (
        expected["base"], expected["signature"]
    )


@pytest.mark.parametrize("case", cases("responses.json"))
def test_response_accept_vectors(case):
    data = load("responses.json")
    GENERATOR.verify(case["request"], now=case["now"], policy=data["policy"], keys=data["keys"])
    verdict = run(case, data)
    expected = case["expected"]
    assert verdict.keyid == expected["keyid"]
    assert serialized(verdict.covered) == expected["covered"]
    assert GENERATOR.expected_base(case["request"], case["response"], keys=data["keys"]) == (
        expected["base"], expected["signature"]
    )


def test_the_sha_512_cases_are_marked_verify_only():
    data = load("requests.json")
    ids = {case["id"] for case in data["cases"]}
    assert set(data["verify_only"]) <= ids
    for case in data["cases"]:
        digest = case["request"]["headers"].get("Content-Digest", "")
        if digest and not digest.startswith("sha-256=") or "," in digest:
            assert case["id"] in data["verify_only"]


# --- the refusals ---

@pytest.mark.parametrize("case", cases("refusals.json"))
def test_refusal_vectors(case):
    """Each case has one defect and so one correct code under the profile's section 9 order."""
    data = load("refusals.json")
    if case.get("verified_by_fiki") is False:
        # Carried as data (@4tkkp50h): fiki has no legacy mode to detect it with.
        assert case["error"] == "mode-mismatch"
        assert case["why"]
        return
    with pytest.raises(FikiError) as caught:
        if case["kind"] == "sign-request":
            request = case["request"]
            sign_request(
                key=Key.from_seed(bytes.fromhex(case["seed_hex"])), method=request["method"],
                url=request["url"], headers=request["headers"], body=body_of(request),
                covered=case["covered"], keyid=case["keyid"],
                minimum=data["policy"]["request_minimum"],
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

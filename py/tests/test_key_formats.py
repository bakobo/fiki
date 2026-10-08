"""fiki-py runs the key-spelling vectors, ``vectors/keys/keys.json`` (``this.i`` @0mvgkwnl).

``aid_from`` turns any of the public-key spellings into the canonical AID, and ``Key.from_openssh``
loads an unencrypted OpenSSH private key. Neither touches the wire: a fiki-signed request still
carries the raw key in its keyid (@7xrx5evg), and a verifier still compares AIDs.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import pytest

from fiki import KEY_VECTORS_FORMAT, Key, aid_from, sign_request, verify_request
from fiki.errors import MalformedKey

KEYS = Path(__file__).resolve().parents[2] / "vectors" / "keys" / "keys.json"
VECTORS = json.loads(KEYS.read_text(encoding="utf-8"))


def _cases(section: str, kind: str) -> list:
    return [pytest.param(case, id=case["id"]) for case in VECTORS[section][kind]]


def test_the_file_declares_the_format_this_port_satisfies():
    assert VECTORS["key_vectors_format"] == KEY_VECTORS_FORMAT


@pytest.mark.parametrize("case", _cases("public", "accepts"))
def test_a_public_spelling_converts_to_its_aid(case):
    assert aid_from(case["input"]) == case["aid"]


@pytest.mark.parametrize("case", _cases("public", "refusals"))
def test_a_malformed_public_spelling_is_refused(case):
    assert case["error"] == "MalformedKey"
    with pytest.raises(MalformedKey) as caught:
        aid_from(case["input"])
    assert type(caught.value) is MalformedKey


@pytest.mark.parametrize("case", _cases("private", "accepts"))
def test_an_openssh_key_loads_and_signs_as_its_seed(case):
    key = Key.from_openssh(case["input"])
    assert key.aid == case["aid"]
    signature = key.sign(VECTORS["signed_message"].encode("ascii"))
    assert base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=") == case["signature"]


@pytest.mark.parametrize("case", _cases("private", "refusals"))
def test_a_malformed_openssh_key_is_refused_without_echoing_it(case):
    assert case["error"] == "MalformedKey"
    with pytest.raises(MalformedKey) as caught:
        Key.from_openssh(case["input"])
    assert type(caught.value) is MalformedKey
    # A private key never reaches an error: not its text, not any run of its base64 body long
    # enough to carry key material, and not the keyid field a consumer might log.
    assert caught.value.keyid == ""
    message = str(caught.value)
    for run in re.findall(r"[A-Za-z0-9+/=]{16,}", case["input"]):
        assert run not in message


@pytest.mark.parametrize(
    "case",
    [pytest.param(c, id=c["id"]) for c in VECTORS["public"]["refusals"]
     if c["id"].endswith(("small-order", "not-on-curve"))],
)
def test_a_weak_key_is_refused_for_its_weakness_whatever_its_spelling(case):
    # Not merely refused: refused by the point check, so the spelling parsed and the key reached
    # it (@37wdchu5). A parser bug that refused these earlier would pass the vector alone.
    with pytest.raises(MalformedKey, match="small order|canonical encoding of a point"):
        aid_from(case["input"])


def test_a_private_key_with_a_weak_public_key_is_refused():
    case = next(c for c in VECTORS["private"]["refusals"] if c["id"] == "public-small-order")
    with pytest.raises(MalformedKey, match="does not derive|small order"):
        Key.from_openssh(case["input"])


def test_a_public_refusal_carries_the_spelling_it_refused():
    with pytest.raises(MalformedKey) as caught:
        aid_from("did:key:zzz")
    assert caught.value.keyid == "did:key:zzz"


def test_an_oversized_public_spelling_is_not_carried_into_the_error():
    text = "x" * (VECTORS["max_public_chars"] + 1)
    with pytest.raises(MalformedKey) as caught:
        aid_from(text)
    assert caught.value.keyid == ""
    assert text not in str(caught.value)


def test_the_encrypted_refusal_says_to_keep_a_dedicated_key():
    case = next(c for c in VECTORS["private"]["refusals"] if c["id"] == "encrypted")
    with pytest.raises(MalformedKey, match="dedicated"):
        Key.from_openssh(case["input"])


def test_an_ssh_key_signs_a_request_that_verifies_against_its_registered_public_line():
    private = next(c for c in VECTORS["private"]["accepts"] if c["id"] == "ssh-keygen")
    public = next(c for c in VECTORS["public"]["accepts"] if c["id"] == "ssh-keygen-pub")
    key = Key.from_openssh(private["input"])
    headers = sign_request(key=key, method="GET", url="https://example.com/x")
    verdict = verify_request(
        method="GET", url="https://example.com/x", headers=headers, max_age=60,
        expected_aid=aid_from(public["input"]),
    )
    assert verdict.aid == aid_from(public["input"])

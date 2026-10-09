"""Every implementation runs the shared vectors at the repository root (``this.i`` @5gf6r08f).

RFC 9421's Appendix B is fiki's first oracle and it does not reach far enough. B.2.6 covers
neither ``@query`` nor ``content-digest`` — its own test request carries ``?param=Value&Pet=dog``
and a body and signs neither — so the two protections fiki adds beyond heti would have no external
oracle at all. These vectors are that oracle, and they are at the repository root rather than
under ``py/`` so a Go or JS port checks itself against the same bytes rather than its own copy.

This module is deliberately a thin driver. Everything a port needs is in the JSON; a port that
reimplements this file in its own language has reimplemented the whole conformance suite.
"""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path

import pytest

from fiki import (VECTORS_FORMAT, Key, Request, sign_request, sign_response, signature_base,
                  verify_request, verify_response)
from fiki.errors import FikiError

VECTORS = Path(__file__).resolve().parents[2] / "vectors"


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def cases(name: str):
    data = load(name)
    return [pytest.param(case, id=case["id"]) for case in data["cases"]]


@pytest.mark.parametrize("name", ["aid-lens.json", "signature-base.json", "accepts.json", "refusals.json",
                                  "misuse.json", "signs.json", "responses.json"])
def test_this_port_satisfies_the_vectors_format_it_is_running(name):
    """A port running newer vectors fails here rather than passing a subset (@4fhrre0m).

    Without this, a vectors bump that added a required behaviour would leave every port quietly
    reporting conformance to a contract it no longer meets — the cases it never implemented would
    simply not be in the file it last read.
    """
    assert load(name)["vectors_format"] == VECTORS_FORMAT


def test_the_vectors_are_where_every_port_can_reach_them():
    """A port that cannot find these has forked them, which is what the layout exists to prevent."""
    # The repository root as git knows it, not a directory name: a worktree or a clone under
    # another name holds the vectors in exactly the right place.
    root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=Path(__file__).resolve().parent,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert VECTORS.is_dir()
    assert VECTORS == Path(root).resolve() / "vectors"


@pytest.mark.parametrize("case", cases("aid-lens.json"))
def test_aid_lens(case):
    """A seed to its AID and back. The one thing here RFC 9421 knows nothing about."""
    key = Key.from_seed(bytes.fromhex(case["seed_hex"]))
    assert key.aid == case["aid"]
    assert base64.urlsafe_b64encode(bytes.fromhex(case["public_key_hex"])).decode().rstrip("=") == (
        case["keyid"]
    )


@pytest.mark.parametrize("case", cases("signature-base.json"))
def test_signature_base_vectors(case):
    """Byte equality on the base, which is where two implementations actually disagree."""
    base = signature_base(
        method=case["method"],
        url=case["url"],
        headers=case["headers"],
        covered=case["covered"],
        created=case["created"],
        keyid=case["keyid"],
        alg=case.get("alg"),
    )
    assert base.decode("utf-8") == case["base"]


@pytest.mark.parametrize("case", cases("signature-base.json"))
def test_signature_vectors(case):
    """Ed25519 is deterministic, so a port that builds the right base produces the right bytes."""
    base = signature_base(
        method=case["method"],
        url=case["url"],
        headers=case["headers"],
        covered=case["covered"],
        created=case["created"],
        keyid=case["keyid"],
        alg=case.get("alg"),
    )
    signature = Key.from_seed(bytes.fromhex(case["seed_hex"])).sign(base)
    assert base64.b64encode(signature).decode("ascii") == case["signature"]


# Every field a verify case may carry. A field this driver does not know fails the case rather
# than being ignored, so a field added to the vectors cannot be silently dropped by a port that
# never learned it (review V-M8).
_VERIFY_FIELDS = {"id", "method", "url", "headers", "body", "max_age", "now", "minimum",
                  "authorities", "expected_aid", "note", "error", "aid", "keyid", "covered",
                  "omit", "kind", "status", "request", "expected_keyid"}
_SIGN_FIELDS = {"id", "kind", "seed_hex", "method", "url", "headers", "body", "covered", "created",
                "expires", "nonce", "tag", "minimum", "status", "request", "expected_headers",
                "error", "note", "keyid", "label"}


def _well_formed(error: Exception) -> None:
    """Every refusal's message holds no control character and is at most 1024 characters, so an
    untrusted value is quoted escaped and cut (@524c8qgv, part-two refinements)."""
    message = str(error)
    assert len(message) <= 1024, len(message)
    assert not any(ord(c) < 0x20 or ord(c) == 0x7F for c in message), repr(message[:200])


def _policy(case) -> dict:
    """The verifier's stated policy (format 3, @524c8qgv): "default" is the port's own default,
    null the explicit opt-out, a list that minimum. authorities is always stated."""
    assert set(case) <= _VERIFY_FIELDS, f"unknown fields {set(case) - _VERIFY_FIELDS}"
    policy = {"authorities": case["authorities"], "expected_aid": case["expected_aid"]}
    if case["minimum"] != "default":
        policy["minimum"] = case["minimum"]
    for name in case.get("omit", []):
        del policy[name]
    return policy


@pytest.mark.parametrize("name", ["accepts.json", "refusals.json", "misuse.json", "signs.json",
                                  "responses.json"])
def test_the_verify_vectors_are_not_empty(name):
    assert len(load(name)["cases"]) >= 5


def _request_of(message):
    if message is None:
        return None
    return Request(method=message["method"], url=message["url"], headers=message["headers"],
                   body=None if message["body"] is None else message["body"].encode("utf-8"))


def _response_policy(case) -> dict:
    assert set(case) <= _VERIFY_FIELDS, f"unknown fields {set(case) - _VERIFY_FIELDS}"
    policy = {"expected_keyid": case["expected_keyid"]}
    if case["minimum"] != "default":
        policy["minimum"] = case["minimum"]
    for name in case.get("omit", []):
        del policy[name]
    return policy


def _verify_response(case):
    return verify_response(
        status=case["status"], headers=case["headers"],
        body=None if case["body"] is None else case["body"].encode("utf-8"),
        request=_request_of(case["request"]), max_age=case["max_age"], now=case["now"],
        **_response_policy(case),
    )


@pytest.mark.parametrize("case", cases("responses.json"))
def test_response_vectors(case):
    """verify_response's own policy (format 3): RESPONSE_MINIMUM by default, expected_keyid stated."""
    if "error" in case:
        with pytest.raises(FikiError) as caught:
            _verify_response(case)
        assert type(caught.value).__name__ == case["error"]
        _well_formed(caught.value)
    else:
        verdict = _verify_response(case)
        assert verdict.keyid == case["keyid"]
        assert [str(c) if not isinstance(c, str) else c for c in verdict.covered] == case["covered"]


@pytest.mark.parametrize("case", cases("signs.json"))
def test_sign_vectors(case):
    """What the signer emits, byte for byte (review V-C4)."""
    assert set(case) <= _SIGN_FIELDS, f"unknown fields {set(case) - _SIGN_FIELDS}"
    key = Key.from_seed(bytes.fromhex(case["seed_hex"]))
    args = dict(key=key, headers=case["headers"],
                body=None if case["body"] is None else case["body"].encode("utf-8"),
                covered=case["covered"], created=case["created"], expires=case["expires"],
                nonce=case["nonce"], tag=case["tag"], minimum=case["minimum"],
                keyid=case["keyid"], label=case["label"])

    def sign():
        if case["kind"] == "request":
            return sign_request(method=case["method"], url=case["url"], **args)
        return sign_response(status=case["status"], request=_request_of(case["request"]), **args)

    if case.get("error") == "caller":
        with pytest.raises((TypeError, ValueError)) as caught:
            sign()
        assert not isinstance(caught.value, FikiError)
    elif "error" in case:
        with pytest.raises(FikiError) as caught:
            sign()
        assert type(caught.value).__name__ == case["error"]
        _well_formed(caught.value)
    else:
        assert sign() == case["expected_headers"]


@pytest.mark.parametrize("case", cases("misuse.json"))
def test_misuse_vectors(case):
    """A mistake in the call is Python's TypeError or ValueError, never a FikiError (@5zrf8gjk)."""
    assert case["error"] == "caller"
    if case.get("kind") == "response":
        with pytest.raises((TypeError, ValueError)) as caught:
            _verify_response(case)
        assert not isinstance(caught.value, FikiError)
        return
    with pytest.raises((TypeError, ValueError)) as caught:
        verify_request(
            method=case["method"],
            url=case["url"],
            headers=case["headers"],
            body=None if case["body"] is None else case["body"].encode("utf-8"),
            max_age=case["max_age"],
            now=case["now"],
            **_policy(case),
        )
    assert not isinstance(caught.value, FikiError)


@pytest.mark.parametrize("case", cases("refusals.json"))
def test_refusal_vectors(case):
    """The negative half. A port that verifies these instead of refusing them is not fiki.

    Every entry names the error class fiki raises, so a port can map its own type onto the same
    condition rather than inventing a taxonomy of its own.
    """
    with pytest.raises(FikiError) as caught:
        verify_request(
            method=case["method"],
            url=case["url"],
            headers=case["headers"],
            body=None if case["body"] is None else case["body"].encode("utf-8"),
            max_age=case["max_age"],
            now=case["now"],
            **_policy(case),
        )
    assert type(caught.value).__name__ == case["error"]
    _well_formed(caught.value)


@pytest.mark.parametrize("case", cases("accepts.json"))
def test_accept_vectors(case):
    """The positive half. A port that refuses these is not fiki either.

    signature-base.json pins what a signer produces and refusals.json pins what a verifier
    rejects; between them nothing said a well-formed request must VERIFY. A port could have
    passed every other vector while returning the wrong AID or the wrong covered set.
    """
    verdict = verify_request(
        method=case["method"],
        url=case["url"],
        headers=case["headers"],
        body=None if case["body"] is None else case["body"].encode("utf-8"),
        max_age=case["max_age"],
        now=case["now"],
        **_policy(case),
    )
    assert verdict.aid == case["aid"]
    # Format 2 (@5zrf8gjk): the keyid exactly as it arrived, beside the identity that vouched.
    assert verdict.keyid == case["keyid"]
    assert list(verdict.covered) == case["covered"]

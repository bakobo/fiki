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
from pathlib import Path

import pytest

from fiki import Key, signature_base, verify_request
from fiki.errors import FikiError

VECTORS = Path(__file__).resolve().parents[2] / "vectors"


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def cases(name: str):
    data = load(name)
    return [pytest.param(case, id=case["id"]) for case in data["cases"]]


def test_the_vectors_are_where_every_port_can_reach_them():
    """A port that cannot find these has forked them, which is what the layout exists to prevent."""
    assert VECTORS.is_dir()
    assert VECTORS.name == "vectors"
    assert VECTORS.parent.name == "fiki"


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
            max_age=case.get("max_age"),
            now=case.get("now"),
        )
    assert type(caught.value).__name__ == case["error"]

"""Keys and the AID lens (``this.i`` @07wstqk7).

The lens is the one thing here RFC 9421 knows nothing about, so it is pinned by fiki's own tests
and, later, by the shared ``vectors/`` every language port runs.
"""

from __future__ import annotations

import pytest

from fiki import Key, verifying_key
from fiki.errors import MalformedKey

# heti derives this same AID from this same seed through keripy's Signer, which is what keeps the
# two libraries' key types interchangeable over one seed.
SEED = bytes(range(32))
AID = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"


def test_from_seed_renders_the_expected_aid():
    assert Key.from_seed(SEED).aid == AID


def test_an_aid_is_44_characters_and_b_prefixed():
    aid = Key.generate().aid
    assert len(aid) == 44
    assert aid.startswith("B")


def test_generate_produces_a_distinct_key_each_time():
    assert Key.generate().aid != Key.generate().aid


def test_the_seed_round_trips_so_a_caller_can_persist_it():
    key = Key.generate()
    assert Key.from_seed(key.seed).aid == key.aid


def test_from_seed_refuses_a_seed_of_the_wrong_length():
    with pytest.raises(MalformedKey):
        Key.from_seed(bytes(31))


def test_verifying_key_recovers_the_key_that_signed():
    key = Key.from_seed(SEED)
    signature = key.sign(b"whatever")
    # No exception means the signature verified.
    verifying_key(key.aid).verify(signature, b"whatever")


@pytest.mark.parametrize(
    "aid",
    [
        pytest.param("B" + "A" * 42, id="too-short"),
        pytest.param("B" + "A" * 44, id="too-long"),
        pytest.param("D" + "A" * 43, id="transferable-prefix"),
        pytest.param("A" * 44, id="no-code"),
        pytest.param("", id="empty"),
    ],
)
def test_verifying_key_refuses_anything_that_is_not_a_non_transferable_aid(aid):
    with pytest.raises(MalformedKey):
        verifying_key(aid)


@pytest.mark.parametrize(
    "aid",
    [
        # Right length and right prefix, wrong alphabet. The two cases differ in how they fail:
        # the first leaves too few valid characters to form base64 at all, the second leaves a
        # well-formed but short decode. Both must surface as fiki's own error rather than as
        # whatever the base64 or Ed25519 layer happens to raise.
        pytest.param("B" + "!" * 43, id="no-valid-characters"),
        pytest.param("B" + "A" * 39 + "!!!!", id="short-after-discarding-invalid"),
        # "=" IS in base64's alphabet, so strict validation accepts these and they decode to 31
        # and 32 bytes — short of a key, from a string of exactly the right length and prefix.
        # Measured, not reasoned: the guard against this was written defensively and the coverage
        # gate then reported it unreached, which is what prompted checking whether it could be.
        pytest.param("B" + "A" * 41 + "==", id="padded-to-31-bytes"),
        pytest.param("B" + "A" * 42 + "=", id="padded-to-32-bytes"),
    ],
)
def test_verifying_key_refuses_a_well_shaped_aid_that_is_not_base64url(aid):
    with pytest.raises(MalformedKey):
        verifying_key(aid)

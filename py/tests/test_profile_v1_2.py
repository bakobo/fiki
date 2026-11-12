"""What KERI profile version 1.2 asks of fiki-py beyond 1.1 (``this.i`` @37rktct3, @84nt4je0).

Two rules, each a library behaviour rather than vector data. Under a resolver, where the keyid is
an AID, a ``B`` keyid's key is the prefix's and must lie in the prime-order subgroup, and an AID is
any of keripy's PreDex prefix codes (@37rktct3). Content no header announced is refused at the
body stage, after the signature and freshness checks, so a message with two defects gets one code
whichever kind of verifier reads it (@84nt4je0).

The mixed-order oracle here builds its torsion point from the curve equation (test_weak_keys's
order-8 points) and adds it in affine coordinates, not the extended ones fiki uses, so a wrong
check and a wrong oracle cannot agree by sharing a method.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from test_weak_keys import D, P, small_order_points, tonelli_shanks, x_squared

from fiki import Key, Request, sign_request, sign_response, verify_request, verify_response
from fiki.errors import (
    InsufficientCoverage,
    MalformedKey,
    SignatureMismatch,
    SignatureTooOld,
    UnknownKey,
    UnsupportedAlgorithm,
)
from fiki.keys import well_formed_aid

KEY = Key.from_seed(bytes(range(32)))
URL = "https://keria.example.com/identifiers?type=rot"
BODY = b'{"hello": "world"}'
AT = 1700000000
L = 2**252 + 27742317777372353535851937790883648493


def raw(key: Key) -> bytes:
    return base64.urlsafe_b64decode("A" + key.aid[1:])[1:]


def cesr(code: str, data: bytes) -> str:
    """CESR's arithmetic: zero bytes in front to a multiple of three, base64url, and the code in
    place of the characters those bytes became."""
    pad = (3 - len(data) % 3) % 3
    return code + base64.urlsafe_b64encode(bytes(pad) + data).decode()[pad:]


# --- a mixed-order key, built in affine coordinates ---

def affine_add(p1, p2):
    (x1, y1), (x2, y2) = p1, p2
    t = D * x1 * x2 * y1 * y2 % P
    return ((x1 * y2 + y1 * x2) * pow(1 + t, -1, P) % P,
            (y1 * y2 + x1 * x2) * pow(1 - t, -1, P) % P)


def decode(raw_bytes: bytes):
    y = int.from_bytes(raw_bytes, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = tonelli_shanks(x_squared(y))
    return (P - x if x & 1 != sign else x), y


def encode(point) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def order_eight():
    for x, y in small_order_points():
        point, n = (x, y), 1
        while point != (0, 1):
            point, n = affine_add(point, (x, y)), n + 1
        if n == 8:
            return x, y
    raise AssertionError("no point of order 8")


MIXED = encode(affine_add(decode(raw(KEY)), order_eight()))
B_MIXED = cesr("B", MIXED)
B_WEAK = cesr("B", b"\x01" + bytes(31))
E_AID = cesr("E", hashlib.sha256(b"a transferable AID").digest())


def sign(keyid, **overrides):
    args = dict(key=KEY, method="POST", url=URL, headers={}, body=BODY, created=AT, keyid=keyid)
    args.update(overrides)
    headers = dict(args["headers"])
    headers.update(sign_request(**args))
    return {"method": args["method"], "url": args["url"], "body": args["body"]}, headers


def verify(request, headers, **overrides):
    args = dict(headers=headers, max_age=300, authorities=None, now=AT, **request)
    args.update(overrides)
    return verify_request(**args)


def never(keyid):
    raise AssertionError(f"the resolver was asked about {keyid}")


def test_the_oracle_key_is_on_the_curve_and_not_in_the_prime_order_subgroup():
    point = decode(MIXED)
    assert x_squared(point[1]) == point[0] * point[0] % P
    multiple, n = point, L - 1
    acc = (0, 1)
    while n:  # [L]P by double-and-add in affine coordinates
        if n & 1:
            acc = affine_add(acc, multiple)
        multiple, n = affine_add(multiple, multiple), n >> 1
    assert affine_add(acc, point) != (0, 1)


# --- B keyids under a resolver: the prefix's key, never the resolver's (@37rktct3) ---

def test_a_b_keyid_is_verified_from_its_prefix_without_asking_the_resolver():
    request, headers = sign(KEY.aid)
    assert verify(request, headers, resolve=never).keyid == KEY.aid


def test_a_mixed_order_b_keyid_is_malformed_under_a_resolver():
    request, headers = sign(B_MIXED)
    with pytest.raises(MalformedKey) as caught:
        verify(request, headers, resolve=never)
    assert caught.value.keyid == B_MIXED


def test_a_mixed_order_expected_aid_is_malformed():
    """expected_aid names its key by an AID too, so the key must lie in the subgroup (profile R1)."""
    request, headers = sign(B_MIXED)
    with pytest.raises(MalformedKey) as caught:
        verify(request, headers, expected_aid=B_MIXED)
    assert caught.value.keyid == B_MIXED


@pytest.mark.parametrize("keyid", [B_WEAK, B_MIXED], ids=["small-order", "mixed-order"])
def test_a_weak_b_keyid_is_malformed_before_the_expected_keyid_is_compared(keyid):
    request, headers = sign(keyid)
    with pytest.raises(MalformedKey):
        verify(request, headers, resolve=never, expected_keyid=E_AID)


def test_a_mixed_order_key_from_a_resolver_is_malformed():
    request, headers = sign(E_AID)
    with pytest.raises(MalformedKey):
        verify(request, headers, resolve={E_AID: MIXED}.get)


def test_a_mixed_order_raw_keyid_is_still_fiki_s_own_lens_and_not_refused_for_its_order():
    """vectors_format 4 pins acceptance of a mixed-order raw keyid (@5r75ff4m); only an AID's key
    must lie in the subgroup, so this one reaches the signature check."""
    keyid = base64.urlsafe_b64encode(MIXED).decode().rstrip("=")
    request, headers = sign(keyid)
    with pytest.raises(SignatureMismatch):
        verify(request, headers)


# --- an AID is any of keripy's PreDex codes (@37rktct3) ---

PREDEX = {"B": 32, "D": 32, "E": 32, "F": 32, "G": 32, "H": 32, "I": 32,
          "0D": 64, "0E": 64, "0F": 64, "0G": 64,
          "1AAA": 33, "1AAB": 33, "1AAI": 33, "1AAJ": 33,
          "1AAC": 57, "1AAD": 57, "1AAE": 114}


@pytest.mark.parametrize("code", PREDEX)
def test_every_predex_code_spells_a_well_formed_aid(code):
    keyid = cesr(code, (hashlib.sha512(code.encode()).digest() * 2)[:PREDEX[code]])
    assert well_formed_aid(keyid)
    assert not well_formed_aid(keyid[:-1])
    assert not well_formed_aid(keyid + "A")


@pytest.mark.parametrize("keyid", [
    "A" + "A" * 43, "J" + "A" * 43, "0A" + "A" * 86, "1AAF" + "A" * 44, "1AAD" + "A" * 75,
    "0D" + "g" + "A" * 85, "0D" + "Q" + "A" * 85,
], ids=["code-A", "code-J", "code-0A", "code-1AAF", "1AAD-short", "0D-pad-bit-1", "0D-pad-bit-2"])
def test_other_codes_and_non_canonical_spellings_are_not_aids(keyid):
    assert not well_formed_aid(keyid)


def test_an_ed448_transferable_keyid_with_no_key_state_is_an_unknown_key():
    keyid = cesr("1AAD", bytes(range(57)))
    request, headers = sign(keyid)
    with pytest.raises(UnknownKey):
        verify(request, headers, resolve=lambda k: None)


@pytest.mark.parametrize("code,size", [("1AAA", 33), ("1AAC", 57), ("1AAI", 33)])
def test_a_non_transferable_keyid_other_than_b_is_an_unsupported_algorithm(code, size):
    keyid = cesr(code, bytes([2]) + bytes(range(size - 1)))
    request, headers = sign(keyid)
    with pytest.raises(UnsupportedAlgorithm):
        verify(request, headers, resolve=never)


def test_a_non_transferable_keyid_other_than_the_expected_one_is_unknown_first():
    keyid = cesr("1AAA", bytes([2]) + bytes(range(32)))
    request, headers = sign(keyid)
    with pytest.raises(UnknownKey):
        verify(request, headers, resolve=never, expected_keyid=E_AID)


# --- content no header announced, at the body stage (@84nt4je0) ---

def test_an_unannounced_uncovered_request_body_is_refused_at_the_body_stage():
    request, headers = sign(KEY.aid, body=None)
    with pytest.raises(InsufficientCoverage):
        verify({**request, "body": BODY}, headers, resolve=never, minimum=["@method", "@path",
                                                                           "@query"])


def test_an_unannounced_uncovered_request_body_comes_after_freshness():
    request, headers = sign(KEY.aid, body=None)
    with pytest.raises(SignatureTooOld):
        verify({**request, "body": BODY}, headers, resolve=never, now=AT + 1000,
               minimum=["@method", "@path", "@query"])


def test_an_announced_uncovered_request_body_is_still_refused_at_the_covered_list():
    request, headers = sign(KEY.aid, body=None, minimum=None, headers={"Content-Length": "18"})
    with pytest.raises(InsufficientCoverage):
        verify(request, headers, resolve=never, now=AT + 1000,
               minimum=["@method", "@path", "@query"])


def test_an_uncovered_response_body_is_refused_at_the_covered_list_by_its_content():
    """A client holds the response's content before verifying it, so the covered-list check judges
    it there, ahead of the signature (profile section 9, step 12)."""
    request = Request(method="GET", url=URL, headers={}, body=None)
    headers = sign_response(key=KEY, status=200, request=request, headers={}, body=None,
                            created=AT, keyid=KEY.aid)
    with pytest.raises(InsufficientCoverage):
        verify_response(status=201, headers=headers, body=b'{"done": true}', request=request,
                        max_age=300, now=AT, resolve=never, expected_keyid=KEY.aid)


@pytest.mark.parametrize("clock", [float("nan"), float("inf"), float("-inf"), "not-a-clock", True])
def test_a_clock_that_is_not_a_finite_number_is_a_caller_error_not_a_pass(clock):
    request, headers = sign(KEY.aid)
    with pytest.raises(TypeError):
        verify(request, headers, resolve=never, now=clock)

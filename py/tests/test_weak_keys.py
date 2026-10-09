"""A public key that is small-order or not a canonical on-curve point is MalformedKey (@37wdchu5).

The forgery that motivates this is concrete: under the identity point's key, ``0x01`` followed by
31 zero bytes, the signature ``0x01`` followed by 63 zero bytes satisfies ``[S]B = R + [k]A`` over
any message. So each path a key can arrive by is driven with that forgery and must refuse it as
a defect in the key, before any signature is examined.

The oracle for which encodings are small-order is derived here from the curve equation with a
general square root (Tonelli-Shanks), not copied from libsodium's blocklist and not computed the
way fiki computes it, so a wrong check and a wrong oracle cannot agree by sharing a method.
"""

from __future__ import annotations

import base64

import pytest

from fiki import Key, sign_request, verify_request, verifying_key
from fiki.errors import MalformedKey, SignatureMismatch
from fiki.keys import public_key, to_aid

P = 2**255 - 19
D = (-121665 * pow(121666, -1, P)) % P

KEY = Key.from_seed(bytes(range(32)))
URL = "https://api.example.com/things?limit=1"
IDENTITY = b"\x01" + bytes(31)
FORGED = b"\x01" + bytes(63)


def is_square(n: int) -> bool:
    return n % P == 0 or pow(n, (P - 1) // 2, P) == 1


def tonelli_shanks(n: int) -> int:
    """A square root mod P by the general algorithm, not RFC 8032's p = 5 mod 8 shortcut."""
    n %= P
    if n == 0:
        return 0
    assert is_square(n)
    q, s = P - 1, 0
    while q % 2 == 0:
        q, s = q // 2, s + 1
    z = 2
    while is_square(z):
        z += 1
    m, c, t, r = s, pow(z, q, P), pow(n, q, P), pow(n, (q + 1) // 2, P)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2, i = t2 * t2 % P, i + 1
        b = pow(c, 1 << (m - i - 1), P)
        m, c, t, r = i, b * b % P, t * b * b % P, r * b % P
    return r


def x_squared(y: int) -> int:
    """From -x^2 + y^2 = 1 + d x^2 y^2: x^2 = (y^2 - 1) / (d y^2 + 1)."""
    return (y * y - 1) * pow(D * y * y + 1, -1, P) % P


def encode(x: int, y: int) -> bytes:
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def small_order_points() -> list[tuple[int, int]]:
    """The eight points whose order divides 8.

    Order 1 and 2 are (0, 1) and (0, -1); order 4 is y = 0. Order 8 is where doubling lands on
    y = 0, which with a = -1 is x^2 = -y^2, and putting that into the curve equation gives
    d y^4 + 2 y^2 - 1 = 0, a quadratic in y^2.
    """
    ys = [1, P - 1, 0]
    disc = tonelli_shanks(4 + 4 * D)
    for root in (disc, P - disc):
        y2 = (-2 + root) * pow(2 * D, -1, P) % P
        if is_square(y2):
            y = tonelli_shanks(y2)
            ys += [y, P - y]
    points = []
    for y in ys:
        x = tonelli_shanks(x_squared(y))
        points += [(x, y)] if x == 0 else [(x, y), (P - x, y)]
    return points


def small_order_encodings() -> list[bytes]:
    """All fourteen: the eight canonical ones, the sign bit set on x = 0, and y + p where it fits."""
    points = small_order_points()
    out = [encode(x, y) for x, y in points]
    out += [(y | (1 << 255)).to_bytes(32, "little") for x, y in points if x == 0]
    out += [
        ((y + P) | (sign << 255)).to_bytes(32, "little")
        for y in {y for _, y in points}
        if y + P < 2**255
        for sign in (0, 1)
    ]
    return out


def keyid_of(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def forged_request(keyid: str):
    headers = sign_request(key=KEY, method="GET", url=URL, keyid=keyid)
    headers["Signature"] = f"sig=:{base64.b64encode(FORGED).decode()}:"
    return headers


def off_curve_y() -> int:
    y = 2
    while is_square(x_squared(y)):
        y += 1
    return y


def large_order_alias() -> bytes:
    """y + p for a small y that is on the curve and not small-order: the same point, misspelled."""
    small = {y for _, y in small_order_points()}
    y = next(y for y in range(2, 19) if y not in small and is_square(x_squared(y)))
    return (y + P).to_bytes(32, "little")


SMALL = small_order_encodings()
NOT_ON_CURVE = [
    pytest.param(off_curve_y().to_bytes(32, "little"), id="y-off-curve"),
    pytest.param(large_order_alias(), id="y-at-or-above-p"),
    pytest.param(b"\xff" * 31 + b"\x7f", id="y-is-2^255-1"),
]


def test_the_oracle_finds_eight_distinct_points_on_the_curve_and_fourteen_encodings():
    points = small_order_points()
    assert len(set(points)) == 8
    for x, y in points:
        assert (-x * x + y * y - 1 - D * x * x * y * y) % P == 0
    assert len(set(SMALL)) == 14
    assert IDENTITY in SMALL


def test_the_forged_signature_is_refused_on_the_raw_keyid_path():
    headers = forged_request(keyid_of(IDENTITY))
    with pytest.raises(MalformedKey) as caught:
        verify_request(authorities=None, method="GET", url=URL, headers=headers, max_age=None)
    assert caught.value.keyid == keyid_of(IDENTITY)


def test_the_forged_signature_is_refused_on_the_resolver_path():
    headers = forged_request("EAnyTransferableAidAtAll")
    with pytest.raises(MalformedKey):
        verify_request(authorities=None, method="GET", url=URL, headers=headers, max_age=None,
                       resolve=lambda keyid: IDENTITY)


def test_the_forged_signature_is_refused_under_an_expected_aid():
    headers = forged_request(keyid_of(IDENTITY))
    with pytest.raises(MalformedKey):
        verify_request(authorities=None, method="GET", url=URL, headers=headers, max_age=None,
                       expected_aid=to_aid(IDENTITY))


@pytest.mark.parametrize("raw", SMALL, ids=[r.hex() for r in SMALL])
def test_every_small_order_encoding_is_malformed_as_a_keyid(raw):
    headers = forged_request(keyid_of(raw))
    with pytest.raises(MalformedKey):
        verify_request(authorities=None, method="GET", url=URL, headers=headers, max_age=None)


@pytest.mark.parametrize("raw", SMALL, ids=[r.hex() for r in SMALL])
def test_every_small_order_encoding_is_malformed_from_a_resolver(raw):
    headers = forged_request("EAnyTransferableAidAtAll")
    with pytest.raises(MalformedKey):
        verify_request(authorities=None, method="GET", url=URL, headers=headers, max_age=None,
                       resolve=lambda keyid: raw)


@pytest.mark.parametrize("raw", SMALL, ids=[r.hex() for r in SMALL])
def test_every_small_order_encoding_is_malformed_as_an_aid(raw):
    with pytest.raises(MalformedKey):
        verifying_key(to_aid(raw))


@pytest.mark.parametrize("raw", NOT_ON_CURVE)
def test_a_key_that_is_not_a_canonical_curve_point_is_malformed_not_a_mismatch(raw):
    headers = sign_request(key=KEY, method="GET", url=URL, keyid=keyid_of(raw))
    with pytest.raises(MalformedKey):
        verify_request(authorities=None, method="GET", url=URL, headers=headers, max_age=None)
    with pytest.raises(MalformedKey):
        verify_request(authorities=None, method="GET", url=URL, headers=headers, max_age=None,
                       resolve=lambda keyid: raw)
    with pytest.raises(MalformedKey):
        verifying_key(to_aid(raw))


def test_an_honest_key_still_verifies_on_every_path():
    raw = verifying_key(KEY.aid).public_bytes_raw()
    headers = sign_request(key=KEY, method="GET", url=URL)
    assert verify_request(authorities=None, method="GET", url=URL, headers=headers, max_age=None).aid == KEY.aid
    assert verify_request(authorities=None, method="GET", url=URL, headers=headers, max_age=None,
                          resolve=lambda keyid: raw).keyid == keyid_of(raw)
    assert verify_request(authorities=None, method="GET", url=URL, headers=headers, max_age=None,
                          expected_aid=KEY.aid).aid == KEY.aid


def test_a_forgery_under_an_honest_key_is_still_a_mismatch():
    headers = sign_request(key=KEY, method="GET", url=URL)
    headers["Signature"] = f"sig=:{base64.b64encode(FORGED).decode()}:"
    with pytest.raises(SignatureMismatch):
        verify_request(authorities=None, method="GET", url=URL, headers=headers, max_age=None)


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_the_public_key_helper_refuses_any_length_but_32_as_malformed(length):
    """Every caller checks the length first today; the helper does not rely on that."""
    with pytest.raises(MalformedKey) as caught:
        public_key(b"\x09" * length, "k")
    assert caught.value.keyid == "k"

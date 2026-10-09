"""verify_request fails closed by default (``this.i`` @524c8qgv).

The shared vectors pin what the default minimum refuses and accepts. These pin the API around it,
which a vector cannot: authorities is a required decision, and only a collection of strings is
one, because a bare string would make ``in`` a substring test (review A3).
"""

from __future__ import annotations

import inspect

import pytest

from fiki import DEFAULT_COVERED, DEFAULT_MINIMUM, REQUEST_MINIMUM, Key, sign_request, verify_request

KEY = Key.from_seed(bytes(range(32)))
URL = "https://api.example.com/things?limit=1"


def _signed():
    return dict(method="GET", url=URL, headers=sign_request(key=KEY, method="GET", url=URL),
                max_age=None)


def test_authorities_has_no_default():
    parameter = inspect.signature(verify_request).parameters["authorities"]
    assert parameter.default is inspect.Parameter.empty
    with pytest.raises(TypeError, match="authorities"):
        verify_request(**_signed())


def test_the_default_minimum_is_fikis_own_signing_default_and_covers_the_profiles():
    assert tuple(DEFAULT_MINIMUM) == tuple(DEFAULT_COVERED)
    assert set(REQUEST_MINIMUM) <= set(DEFAULT_MINIMUM)
    assert repr(inspect.signature(verify_request).parameters["minimum"].default) == "DEFAULT_MINIMUM"


@pytest.mark.parametrize("authorities", ["api.example.com", b"api.example.com",
                                         bytearray(b"api.example.com"), 42],
                         ids=["str", "bytes", "bytearray", "int"])
def test_authorities_that_are_not_a_collection_of_hosts_are_a_caller_error(authorities):
    with pytest.raises(TypeError, match="collection of the hosts"):
        verify_request(**_signed(), authorities=authorities)


def test_a_substring_of_a_served_host_is_never_served():
    # The fail-open this replaces: "api.example.com" as a string admitted "example.com".
    with pytest.raises(TypeError):
        verify_request(**_signed(), authorities="xapi.example.comx")


def test_an_authority_that_is_not_a_string_is_a_caller_error():
    with pytest.raises(TypeError, match="is not"):
        verify_request(**_signed(), authorities=["api.example.com", 443])


def test_empty_authorities_serve_no_host_and_are_a_caller_error():
    with pytest.raises(ValueError, match="pass None"):
        verify_request(**_signed(), authorities=set())


@pytest.mark.parametrize("authorities", [{"api.example.com"}, ["api.example.com"],
                                         ("x.example", "api.example.com"),
                                         frozenset({"api.example.com"})])
def test_any_collection_of_hosts_serves(authorities):
    assert verify_request(**_signed(), authorities=authorities).aid == KEY.aid


def test_none_declines_the_authority_check():
    assert verify_request(**_signed(), authorities=None).aid == KEY.aid

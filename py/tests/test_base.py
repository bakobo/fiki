"""The signature base builder, beyond what RFC 9421's own vector reaches (``this.i`` @2hwvpm42).

B.2.6 covers ``@method``, ``@path``, ``@authority`` and plain headers, and nothing here repeats
that. What it does not reach is everything below: ``@query``, the authority's port normalization,
and the two refusals — an unbuildable derived component and a covered header the request does not
carry. Those refusals are the reason fiki has a base builder of its own rather than a wrapper, so
they are the part worth testing hardest.
"""

from __future__ import annotations

import pytest

from fiki import signature_base
from fiki.base import Request, response_signature_base
from fiki.errors import MissingComponent, SignatureMismatch, UnsupportedComponent

BASE_ARGS = dict(created=1618884473, keyid="test-key-ed25519")


def line_for(component, **overrides):
    """Return the one base line for a single covered component."""
    args = dict(
        method="POST",
        url="https://example.com/foo?param=Value&Pet=dog",
        headers={},
        covered=[component],
        **BASE_ARGS,
    )
    args.update(overrides)
    return signature_base(**args).decode("utf-8").split("\n")[0]


def test_query_carries_its_leading_question_mark():
    """RFC 9421 section 2.2.7 — the whole query string, percent-encoding untouched."""
    assert line_for("@query") == '"@query": ?param=Value&Pet=dog'


def test_query_of_a_request_with_no_query_is_a_bare_question_mark():
    """Section 2.2.7 again. A signer covering @query on a bare URL still binds "no query"."""
    assert line_for("@query", url="https://example.com/foo") == '"@query": ?'


def test_percent_encoding_in_the_query_is_not_decoded():
    line = line_for("@query", url="https://example.com/p?baz=bat%2Dman")
    assert line == '"@query": ?baz=bat%2Dman'


def test_an_empty_path_is_the_slash_the_origin_server_sees():
    assert line_for("@path", url="https://example.com") == '"@path": /'


def test_authority_lowercases_the_host_and_omits_a_default_port():
    """Section 2.2.3. Both halves matter: a proxy and a client must agree on this string."""
    assert line_for("@authority", url="https://EXAMPLE.com:443/f") == '"@authority": example.com'


@pytest.mark.parametrize(
    "url, authority",
    [
        ("https://[::1]:8443/x", "[::1]:8443"),
        ("https://[::1]/x", "[::1]"),
        ("https://[2001:DB8::1]:443/x", "[2001:db8::1]"),
        ("http://[2001:db8::1]:8080/x", "[2001:db8::1]:8080"),
        # An IPvFuture literal has no colon, and is still an IP-literal (RFC 3986 section 3.2.2).
        ("https://[v1.example]/x", "[v1.example]"),
        ("https://[v1.example]:8443/x", "[v1.example]:8443"),
        ("https://[v1.example]:443/x", "[v1.example]"),
    ],
)
def test_authority_keeps_the_brackets_of_an_ipv6_literal(url, authority):
    """RFC 3986 section 3.2.2 spells an IPv6 host as an IP-literal, brackets included, and RFC
    9421 section 2.2.3 builds @authority from that host (tick 2h2g)."""
    assert line_for("@authority", url=url) == f'"@authority": {authority}'


def test_authority_keeps_a_non_default_port():
    assert line_for("@authority", url="https://example.com:8443/f") == (
        '"@authority": example.com:8443'
    )


def test_method_is_the_method_as_sent_with_no_case_transformation():
    """RFC 9421 section 2.2.1, and @22g0xkr8: "post" and "POST" are different methods."""
    assert line_for("@method", method="post") == '"@method": post'


def test_header_values_are_stripped_and_named_in_lowercase():
    line = line_for("Content-Type", headers={"Content-Type": "  application/json  "})
    assert line == '"content-type": application/json'


def test_a_derived_component_fiki_cannot_build_is_refused_rather_than_skipped():
    """The gap in heti's KERI dialect is exactly a silent skip here (@2hwvpm42)."""
    with pytest.raises(UnsupportedComponent):
        line_for("@target-uri")


def test_a_covered_header_the_request_lacks_is_refused():
    with pytest.raises(MissingComponent):
        line_for("x-absent")


def test_signature_params_serializes_the_optional_parameters_in_a_fixed_order():
    """Order is the signer's choice, so fiki fixes one and keeps it — its output is reproducible."""
    base = signature_base(
        method="POST",
        url="https://example.com/foo",
        headers={},
        covered=["@method"],
        created=1618884473,
        keyid="k",
        alg="ed25519",
        expires=1618884573,
        nonce="abc",
        tag="app",
    )
    assert base.decode("utf-8").split("\n")[-1] == (
        '"@signature-params": ("@method");created=1618884473;expires=1618884573;'
        'nonce="abc";alg="ed25519";keyid="k";tag="app"'
    )


# --- authority when the caller has a path rather than a full URL ---

def test_authority_falls_back_to_the_host_header_when_the_url_has_none():
    """RFC 9421 section 2.2.3 — in HTTP/1.1 the authority IS the Host header.

    A server-side verifier is handed a request target and a header block, not a reconstructed
    absolute URL, and guessing a scheme in order to synthesize one gets the default-port rule
    wrong. heti's vanilla dialect delegates here with exactly that shape.
    """
    line = line_for("@authority", url="/things?limit=1", headers={"Host": "API.example.com"})
    assert line == '"@authority": api.example.com'


def test_a_relative_url_still_yields_path_and_query():
    assert line_for("@path", url="/things?limit=1") == '"@path": /things'
    assert line_for("@query", url="/things?limit=1") == '"@query": ?limit=1'


def test_a_host_header_port_is_preserved_because_no_scheme_declares_it_default():
    line = line_for("@authority", url="/x", headers={"Host": "example.com:8443"})
    assert line == '"@authority": example.com:8443'


def test_covering_authority_with_neither_a_url_authority_nor_a_host_header_is_refused():
    with pytest.raises(MissingComponent):
        line_for("@authority", url="/things")


# Characters str.strip() removes that are not RFC 9110 optional whitespace. Each is refused at the
# edge of a value exactly as inside one, because the check runs on the value as received and only
# SP and HTAB are trimmed afterwards (tick 4r5h).
_EDGE_CONTROLS = ["\r\n", "\r", "\n", "\x0b", "\x0c", "\x1c", "\x85", "\xa0", "\u2003"]


@pytest.mark.parametrize("edge", _EDGE_CONTROLS, ids=[repr(e) for e in _EDGE_CONTROLS])
@pytest.mark.parametrize("where", ["leading", "trailing"])
def test_a_control_character_at_the_edge_of_a_value_is_refused_not_trimmed(edge, where):
    value = edge + "admin" if where == "leading" else "admin" + edge
    with pytest.raises(SignatureMismatch):
        line_for("X-Scope", headers={"X-Scope": value})


@pytest.mark.parametrize("edge", _EDGE_CONTROLS, ids=[repr(e) for e in _EDGE_CONTROLS])
def test_a_control_character_at_the_edge_of_a_host_is_refused_not_trimmed(edge):
    with pytest.raises(SignatureMismatch):
        line_for("@authority", url="/foo", headers={"Host": "example.com" + edge})


def test_only_spaces_and_tabs_are_trimmed_from_the_edges_of_a_value():
    """RFC 9110 section 5.5: SP and HTAB are the optional whitespace around a field value."""
    line = line_for("X-Scope", headers={"X-Scope": " \t admin \t "})
    assert line == '"x-scope": admin'
    assert line_for("@authority", url="/foo", headers={"Host": " Example.com\t"}) == (
        '"@authority": example.com'
    )


def test_an_empty_method_is_a_caller_error_rather_than_an_empty_line():
    """A request has a method; an empty string is a caller who lost it, and signing "@method: "
    would bind nothing a verifier could check."""
    with pytest.raises(ValueError, match="is not an HTTP method"):
        line_for("@method", method="")


def test_a_missing_method_is_a_caller_error():
    with pytest.raises(TypeError, match="method is a string"):
        line_for("@method", method=None)


def test_an_empty_method_is_refused_even_when_nothing_covers_it():
    """The 0.8.0 sweep (@5zrf8gjk): a request message has a token for a method, covered or not."""
    with pytest.raises(ValueError, match="is not an HTTP method"):
        line_for("@path", method="")


def test_an_empty_method_in_the_request_a_response_answers_is_a_caller_error():
    with pytest.raises(ValueError, match="is not an HTTP method"):
        response_signature_base(status=200, headers={}, covered=['"@method";req'],
                                request=Request(method="", url="https://example.com/"),
                                **BASE_ARGS)

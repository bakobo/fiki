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
from fiki.errors import MissingComponent, UnsupportedComponent

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


def test_authority_keeps_a_non_default_port():
    assert line_for("@authority", url="https://example.com:8443/f") == (
        '"@authority": example.com:8443'
    )


def test_method_is_uppercased():
    assert line_for("@method", method="post") == '"@method": POST'


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

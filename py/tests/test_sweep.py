"""The 0.8.0 cross-port sweep: every port gives the same answer to the same input (@5zrf8gjk).

One test group per rule of the sweep, numbered as the spec numbers them, so a port worker can map
each group onto its own suite. Caller errors are tested here and not in the vectors, because they
are API behaviour; everything a vector can pin is also in ``vectors/`` and ``vectors/keri/``.
fiki-py's own reading of the rulings, where the spec leaves a choice, is @9g24rdns.
"""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import SplitResult

import pytest

from fiki import (
    __all__ as EXPORTED,
    KERI_VECTORS_FORMAT,
    MAX_DICTIONARY_MEMBERS,
    MAX_FIELD_BYTES,
    MAX_INNER_LIST_ITEMS,
    MAX_PARAMETERS,
    REQUEST_MINIMUM,
    VECTORS_FORMAT,
    Key,
    Request,
    Verdict,
    req,
    response_signature_base,
    sign_request,
    sign_response,
    signature_base,
    verify_request,
    verify_response,
)
from fiki.errors import (
    InsufficientCoverage,
    MalformedDigest,
    MalformedKey,
    MalformedSignature,
    MalformedSignatureInput,
    MalformedSignatureLabel,
    SignatureMismatch,
    Unauthenticated,
    UnknownKey,
    UnsupportedComponent,
)
from fiki.base import ip_literal
from fiki.messages import content_digest

KEY = Key.from_seed(bytes(range(32)))
URL = "https://api.example.com/things?limit=1"
BODY = b'{"hello": "world"}'
AT = 1700000000
BASE_ARGS = dict(created=AT, keyid="k")


def keyid_of(key: Key) -> str:
    return base64.urlsafe_b64encode(
        base64.urlsafe_b64decode("A" + key.aid[1:])[1:]
    ).decode().rstrip("=")


def sign(**overrides):
    args = dict(key=KEY, method="GET", url=URL, headers={}, body=None, created=AT)
    args.update(overrides)
    headers = dict(args["headers"])
    headers.update(sign_request(**args))
    return {"method": args["method"], "url": args["url"], "body": args["body"]}, headers


def verify(request, headers, **overrides):
    # As in test_profile: 0.8's no-minimum default, stated explicitly (@524c8qgv).
    args = dict(headers=headers, max_age=None, now=AT, authorities=None, minimum=None, **request)
    args.update(overrides)
    return verify_request(**args)


def with_digest(digest: str):
    """A POST validly signed over a Content-Digest of the caller's spelling.

    Built from the base rather than through sign_request, which refuses to sign a digest it cannot
    check against the body (A7), so a test can hand the verifier a header the signer would refuse.
    """
    headers = {"Content-Digest": digest}
    base = signature_base(method="POST", url=URL, headers=headers,
                          covered=["@method", "@authority", "@path", "@query", "content-digest"],
                          created=AT, keyid=keyid_of(KEY), alg="ed25519")
    params = base.decode().rsplit('"@signature-params": ', 1)[1]
    headers["Signature-Input"] = f"sig={params}"
    headers["Signature"] = f"sig=:{base64.b64encode(KEY.sign(base)).decode()}:"
    return {"method": "POST", "url": URL, "body": BODY}, headers


def authority(url: str) -> str:
    base = signature_base(method="GET", url=url, headers={}, covered=["@authority"], **BASE_ARGS)
    return base.decode().split("\n")[0].split(": ", 1)[1]


def cesr(code: str, raw: bytes) -> str:
    return code + base64.urlsafe_b64encode(b"\x00" + raw).decode()[1:]


def flip_pad_bit(aid: str) -> str:
    """bit 4 of the second character lands in the pad byte, so this spells the same 32 bytes."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return aid[0] + alphabet[alphabet.index(aid[1]) ^ 16] + aid[2:]


# --- A3: an IP-literal keeps its brackets, and only :port may follow ']' ---

@pytest.mark.parametrize("url, expected", [
    ("https://[2001:db8::1]:8443/x", "[2001:db8::1]:8443"),
    ("https://[2001:DB8::1]/x", "[2001:db8::1]"),
    ("https://[v1.example]:81/x", "[v1.example]:81"),
])
def test_an_ip_literal_keeps_its_brackets(url, expected):
    assert authority(url) == expected


@pytest.mark.parametrize("url", [
    "https://[::1]x/things", "https://[::1]:443x/things", "https://[::1/things",
    "https://::1]/things",
])
def test_text_after_an_ip_literal_is_a_caller_error_when_signing(url):
    with pytest.raises(ValueError, match="cannot be read: "):
        authority(url)


@pytest.mark.parametrize("url", ["https://[::1]x/things", "https://[::1/things"])
def test_text_after_an_ip_literal_is_a_signature_mismatch_when_verifying(url):
    request, headers = sign(url="https://[::1]/things")
    with pytest.raises(SignatureMismatch):
        verify({**request, "url": url}, headers)


NOT_ADDRESSES = ["not-an-ip", "1.2.3.4", "vZ.x", "v1.", "V1.x", "v.x", "::1%", "fe80::1%a%b",
                 "1:2:3:4:5:6:7:8:9", "::01.2.3.4", "::256.1.1.1", "12345::", "", "1::2::3"]


@pytest.mark.parametrize("inside", NOT_ADDRESSES)
def test_a_bracketed_host_that_is_not_an_address_is_a_caller_error_when_signing(inside):
    with pytest.raises(ValueError, match="urlsplit refuses it"):
        sign(url=f"https://[{inside}]/x")


@pytest.mark.parametrize("inside", NOT_ADDRESSES)
def test_a_bracketed_host_that_is_not_an_address_is_a_signature_mismatch_when_verifying(inside):
    request, headers = sign(url="https://[::1]/x")
    with pytest.raises(SignatureMismatch):
        verify({**request, "url": f"https://[{inside}]/x"}, headers)


@pytest.mark.parametrize("inside", NOT_ADDRESSES)
def test_fiki_checks_an_ip_literal_itself_rather_than_trusting_urlsplit(inside):
    """urlsplit checks the brackets' contents only from Python 3.11.4, and Debian 12 has 3.11.2."""
    assert not ip_literal(inside)


@pytest.mark.parametrize("netloc", ["[not-an-ip]", "[::1]x", "[::1", "a]b[", "a[::1]"])
def test_an_authority_urlsplit_does_not_refuse_is_still_unreadable(netloc, monkeypatch):
    """Before Python 3.11.4, urlsplit refused only an unbalanced bracket."""
    request, headers = sign(url="https://a.example/x")
    lenient = SplitResult("https", netloc, "/x", "", "")
    monkeypatch.setattr("fiki.base.urlsplit", lambda url: lenient)
    with pytest.raises(ValueError, match="cannot be read: "):
        authority("https://a.example/x")
    with pytest.raises(SignatureMismatch):
        verify(request, headers)


@pytest.mark.parametrize("inside", [
    "::1", "::", "1::", "2001:DB8::1", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::ffff:1.2.3.4",
    "1:2:3:4:5:6:1.2.3.4", "fe80::1%25eth0", "v1.x", "vF.a:b", "v12.[",
])
def test_an_ipv6_address_or_ipvfuture_is_an_ip_literal(inside):
    assert ip_literal(inside)
    assert authority(f"https://[{inside}]/x") == f"[{inside.lower()}]"


# --- A4: header names and values are strings ---

@pytest.mark.parametrize("headers", [{None: "x"}, {"x-a": None}, {b"x-a": "1"}, {"x-a": 1}])
def test_a_header_name_or_value_that_is_not_a_string_is_a_caller_error(headers):
    with pytest.raises(TypeError, match="both strings"):
        sign(headers=headers)
    with pytest.raises(TypeError, match="both strings"):
        verify_request(authorities=None, method="GET", url=URL, headers=headers, max_age=None)


# --- A7: a supplied Content-Digest must match the body it is signed with ---

@pytest.mark.parametrize("digest", [
    content_digest(b"another body"),
    "sha-256=:AAAA:",
    "x-unknown=:AAAA:",
    "not a dictionary (((",
])
def test_a_supplied_digest_the_body_does_not_match_is_a_caller_error(digest):
    with pytest.raises(ValueError, match="is not one a verifier would accept"):
        sign(method="POST", body=BODY, headers={"Content-Digest": digest})
    with pytest.raises(ValueError, match="is not one a verifier would accept"):
        sign_response(key=KEY, status=200, body=BODY, headers={"content-digest": digest},
                      created=AT)


def test_a_supplied_digest_that_matches_is_signed_as_given():
    digest = "x-unknown=:AAAA:, " + content_digest(BODY)
    request, headers = sign(method="POST", body=BODY, headers={"Content-Digest": digest})
    assert headers["Content-Digest"] == digest
    assert verify(request, headers).aid == KEY.aid


# --- A8: Content-Length is trimmed of SP and HTAB only ---

@pytest.mark.parametrize("length", ["0 ", "0\x0b", "0\x0c", " 0"])
def test_a_content_length_padded_with_other_whitespace_counts_as_a_body(length):
    request, headers = sign(headers={"Content-Length": length})
    with pytest.raises(InsufficientCoverage):
        verify(request, headers, minimum=REQUEST_MINIMUM)


def test_a_content_length_padded_with_sp_and_htab_is_still_zero():
    request, headers = sign(headers={"Content-Length": " \t0\t "})
    assert verify(request, headers, minimum=REQUEST_MINIMUM).aid == KEY.aid


# --- A10: keyid well-formedness, then the expected keyid, then the resolver ---

def test_a_malformed_raw_keyid_beside_an_expected_keyid_is_malformed_not_unknown():
    request, headers = sign(keyid="not-a-key")
    with pytest.raises(MalformedKey):
        verify(request, headers, expected_keyid=keyid_of(KEY))


def test_a_small_order_raw_keyid_beside_an_expected_keyid_is_malformed_not_unknown():
    identity = base64.urlsafe_b64encode(b"\x01" + bytes(31)).decode().rstrip("=")
    request, headers = sign(keyid=identity)
    with pytest.raises(MalformedKey):
        verify(request, headers, expected_keyid=keyid_of(KEY))


def test_a_misspelled_aid_beside_an_expected_keyid_is_malformed_and_never_resolved():
    aid = cesr("E", hashlib.sha256(b"x").digest())
    calls = []
    request, headers = sign(keyid=flip_pad_bit(aid))
    with pytest.raises(MalformedKey):
        verify(request, headers, expected_keyid=aid, resolve=calls.append)
    assert calls == []


def test_an_unexpected_keyid_is_unknown_without_asking_the_resolver():
    aid = cesr("E", hashlib.sha256(b"x").digest())
    calls = []
    request, headers = sign(keyid=aid)
    with pytest.raises(UnknownKey):
        verify(request, headers, expected_keyid="E" + "A" * 43, resolve=calls.append)
    assert calls == []


# --- A11: a 401 whose Signature header is empty is an unsigned 401 ---

def test_a_401_with_an_empty_signature_header_is_unauthenticated():
    with pytest.raises(Unauthenticated):
        verify_response(expected_keyid=None, minimum=None, status=401, headers={"Signature": ""}, max_age=None)
    with pytest.raises(Unauthenticated):
        verify_response(expected_keyid=None, minimum=None, status=401, headers={"Signature": "", "Signature-Input": "sig=()"},
                        max_age=None)


# --- A12: RFC 8941 parsing is strict ---

@pytest.mark.parametrize("member", ["x=1.", "x=-1.", "x=1.;a=2", "x=(1.)", "x=2;a=1."])
def test_a_decimal_without_a_fractional_digit_is_malformed(member):
    request, headers = with_digest(f"{content_digest(BODY)}, {member}")
    with pytest.raises(MalformedDigest):
        verify(request, headers)


@pytest.mark.parametrize("member", ['x=1.5', 'x="1."', 'x=a1.', 'x=*1.', 'x=:QUFB:', 'x=a:1.'])
def test_what_only_looks_like_a_bare_decimal_is_still_accepted(member):
    request, headers = with_digest(f"{content_digest(BODY)}, {member}")
    assert verify(request, headers).aid == KEY.aid


def test_a_bare_decimal_is_malformed_in_the_other_two_headers():
    request, headers = sign()
    bad = dict(headers, Signature=headers["Signature"] + ";x=1.")
    with pytest.raises(MalformedSignature):
        verify(request, bad)
    bad = dict(headers, **{"Signature-Input": headers["Signature-Input"] + ";x=1."})
    with pytest.raises(MalformedSignatureInput):
        verify(request, bad)


@pytest.mark.parametrize("member", ["x=1234567890123456", "x=:QQ:", "x=:QQ=:", "x=:=:"])
def test_long_integers_and_badly_padded_byte_sequences_are_malformed(member):
    request, headers = with_digest(f"{content_digest(BODY)}, {member}")
    with pytest.raises(MalformedDigest):
        verify(request, headers)


_RFC_9651 = [("x=@1659578233", "Date"), ("x=-@1", None), ("x=2;a=@0", "Date"),
             ("x=(@1)", "Date"), ("x=(1 2;a=@1)", "Date"), ("x=(1);a=@-5", "Date"),
             ('x=%"a"', "Display String"), ('x=%"%c3%a9"', "Display String"),
             ('x=2;a=%"b"', "Display String"), ('x=(%"c")', "Display String"),
             ('x=();a=%""', "Display String")]


@pytest.mark.parametrize("member, kind", _RFC_9651)
def test_a_date_or_display_string_is_malformed_in_a_content_digest(member, kind):
    # RFC 9421 references RFC 8941, which has neither type; http_sfv parses both (@7vdhfv3q).
    request, headers = with_digest(f"{content_digest(BODY)}, {member}")
    with pytest.raises(MalformedDigest, match=kind or "could not parse"):
        verify(request, headers)


@pytest.mark.parametrize("member, kind", [(m, k) for m, k in _RFC_9651 if k])
def test_a_date_or_display_string_is_malformed_in_the_other_two_headers(member, kind):
    request, headers = sign()
    params = member.removeprefix("x=")
    bad = dict(headers, Signature=f"{headers['Signature']}, x={params}")
    with pytest.raises(MalformedSignature, match=kind):
        verify(request, bad)
    bad = dict(headers, **{"Signature-Input": f"{headers['Signature-Input']}, x={params}"})
    with pytest.raises(MalformedSignatureInput, match=kind):
        verify(request, bad)


@pytest.mark.parametrize("member", ['x="@1"', 'x="%\\"a\\""', 'x=a;b="@1"'])
def test_what_only_looks_like_a_date_or_display_string_is_still_accepted(member):
    request, headers = with_digest(f"{content_digest(BODY)}, {member}")
    assert verify(request, headers).aid == KEY.aid


def test_trailing_ows_after_a_dictionary_member_is_accepted():
    request, headers = sign()
    headers["Signature"] += " \t"
    assert verify(request, headers).aid == KEY.aid


# --- B13: the method is a token, on every path ---

@pytest.mark.parametrize("method", ["", " ", "G T", "GET\r\n", "GET\n", "G(T", "café"])
def test_a_method_that_is_not_a_token_is_a_caller_error_wherever_a_request_is_built(method):
    with pytest.raises(ValueError, match="is not an HTTP method"):
        sign(method=method, covered=["@path"])
    with pytest.raises(ValueError, match="is not an HTTP method"):
        signature_base(method=method, url=URL, headers={}, covered=["@path"], **BASE_ARGS)
    request, headers = sign()
    with pytest.raises(ValueError, match="is not an HTTP method"):
        verify({**request, "method": method}, headers)
    with pytest.raises(ValueError, match="is not an HTTP method"):
        response_signature_base(status=200, headers={}, covered=["@status"],
                                request=Request(method=method, url=URL), **BASE_ARGS)
    with pytest.raises(ValueError, match="is not an HTTP method"):
        verify_response(expected_keyid=None, minimum=None, status=200, headers={}, max_age=None,
                        request=Request(method=method, url=URL))


def test_a_method_that_is_not_a_string_is_a_type_error():
    with pytest.raises(TypeError, match="method is a string"):
        sign(method=None, covered=["@path"])
    with pytest.raises(TypeError, match="method is a string"):
        sign(method=b"GET", covered=["@path"])


@pytest.mark.parametrize("method", ["M-SEARCH", "get", "PROPFIND", "x!#$%&'*+.^_`|~1"])
def test_any_token_is_a_method_and_keeps_its_case(method):
    request, headers = sign(method=method)
    assert verify(request, headers).aid == KEY.aid
    base = signature_base(method=method, url=URL, headers={}, covered=["@method"], **BASE_ARGS)
    assert base.decode().startswith(f'"@method": {method}\n')


# --- B14: a port is a run of ASCII digits, read as a number, in 0..65535 ---

@pytest.mark.parametrize("url, expected", [
    ("http://a.example:000080/x", "a.example"),
    ("https://a.example:0443/x", "a.example"),
    ("https://a.example:08443/x", "a.example:8443"),
    ("https://a.example:" + "0" * 200 + "8443/x", "a.example:8443"),
    ("https://a.example:65535/x", "a.example:65535"),
    ("https://a.example:0/x", "a.example:0"),
    ("https://a.example:/x", "a.example"),
    ("https://A.example:81/x", "a.example:81"),
])
def test_a_port_is_read_as_a_number(url, expected):
    assert authority(url) == expected


BAD_PORTS = ["65536", "99999", "8x", "+80", " 80", "-1", "٨٠", "80 ", "0x50", "1e3"]


@pytest.mark.parametrize("port", BAD_PORTS)
def test_a_port_that_is_not_one_is_a_caller_error_when_signing(port):
    with pytest.raises(ValueError, match="cannot be read: "):
        authority(f"https://a.example:{port}/x")
    with pytest.raises(ValueError, match="cannot be read: "):
        sign(url=f"https://a.example:{port}/x")


@pytest.mark.parametrize("port", BAD_PORTS)
def test_a_port_that_is_not_one_is_a_signature_mismatch_when_verifying(port):
    request, headers = sign(url="https://a.example/x")
    with pytest.raises(SignatureMismatch):
        verify({**request, "url": f"https://a.example:{port}/x"}, headers)


def test_a_port_of_thousands_of_leading_zeros_is_read_without_converting_them():
    """Python refuses to convert a string of over 4300 digits, with a ValueError of its own."""
    zeros = "0" * 5000
    assert authority(f"https://a.example:{zeros}443/x") == "a.example"
    assert authority(f"https://a.example:{zeros}8443/x") == "a.example:8443"
    request, headers = sign(url="https://a.example:443/x")
    assert verify({**request, "url": f"https://a.example:{zeros}443/x"}, headers).aid == KEY.aid


@pytest.mark.parametrize("port", ["0" * 5000 + "65536", "1" + "0" * 5000, "9" * 5000])
def test_a_port_of_thousands_of_digits_is_out_of_range(port):
    with pytest.raises(ValueError, match="not a number from 0 to 65535"):
        authority(f"https://a.example:{port}/x")
    request, headers = sign(url="https://a.example/x")
    with pytest.raises(SignatureMismatch):
        verify({**request, "url": f"https://a.example:{port}/x"}, headers)


def test_a_bad_port_is_a_signature_mismatch_in_the_request_a_response_answers():
    asked = Request(method="GET", url="https://a.example/x")
    headers = sign_response(key=KEY, status=200, request=asked, created=AT,
                            covered=["@status", req("@authority")])
    with pytest.raises(SignatureMismatch):
        verify_response(expected_keyid=None, minimum=None, status=200, headers=headers, max_age=None,
                        request=Request(method="GET", url="https://a.example:99999/x"))


def test_a_bad_port_is_never_read_when_authority_is_not_covered():
    request, headers = sign(url="https://a.example/x", covered=["@method", "@path", "@query"])
    assert verify({**request, "url": "https://a.example:99999/x"}, headers).aid == KEY.aid


# --- B15: what the signer serializes must be serializable ---

@pytest.mark.parametrize("label", ["a\r\nb", "Sig", "1sig", "", "si g", "sigé", "-a"])
def test_a_label_that_is_not_an_rfc_8941_key_is_a_caller_error(label):
    with pytest.raises(ValueError, match="is not an RFC 8941 key"):
        sign(label=label)
    with pytest.raises(ValueError, match="is not an RFC 8941 key"):
        sign_response(key=KEY, status=200, created=AT, label=label)


def test_a_label_that_is_not_a_string_is_a_type_error():
    with pytest.raises(TypeError, match="label is a string"):
        sign(label=None)


@pytest.mark.parametrize("label", ["sig", "*", "a1_.-*", "signify"])
def test_any_rfc_8941_key_is_a_label(label):
    request, headers = sign(label=label)
    assert headers["Signature"].startswith(f"{label}=:")
    assert verify(request, headers).aid == KEY.aid


@pytest.mark.parametrize("field", ["keyid", "nonce", "tag"])
@pytest.mark.parametrize("value", ["a\r\nb", "a\nb", "café", "a\x7f", "a\tb", "\x00"])
def test_a_serialized_string_outside_printable_ascii_is_a_caller_error(field, value):
    with pytest.raises(ValueError, match="outside printable ASCII"):
        sign(**{field: value})
    args = dict(BASE_ARGS, **{field: value})
    with pytest.raises(ValueError, match="outside printable ASCII"):
        signature_base(method="GET", url=URL, headers={}, covered=["@path"], **args)


@pytest.mark.parametrize("field", ["keyid", "nonce", "tag"])
def test_a_serialized_string_that_is_not_a_string_is_a_type_error(field):
    with pytest.raises(TypeError, match="is a string; this one is 7"):
        sign(**{field: 7})


@pytest.mark.parametrize("field", ["nonce", "tag"])
def test_every_printable_ascii_character_is_a_serializable_string(field):
    value = "".join(chr(c) for c in range(0x20, 0x7F))
    request, headers = sign(**{field: value})
    assert verify(request, headers).aid == KEY.aid


@pytest.mark.parametrize("name", ["x\r\ny", "a b", "", "x:y", "café", "x\t"])
def test_a_component_name_that_is_not_a_field_name_is_a_caller_error(name):
    with pytest.raises(ValueError, match="is not a component fiki can name"):
        sign(covered=["@method", name], headers={name: "1"} if name else {})


def test_a_serialized_component_whose_name_is_not_a_field_name_is_a_caller_error():
    with pytest.raises(ValueError, match="is not a component fiki can name"):
        sign(covered=['"a b"'])
    with pytest.raises(ValueError, match="is not a component fiki can name"):
        sign_response(key=KEY, status=200, created=AT, covered=["@status", '"a b";req'],
                      request=Request(method="GET", url=URL))


def test_an_unknown_derived_component_keeps_its_own_refusal():
    with pytest.raises(UnsupportedComponent):
        sign(covered=["@target-uri"])


def test_a_field_name_is_still_lowercased_for_a_local_caller():
    request, headers = sign(covered=["@method", "X-Role"], headers={"X-Role": "admin"})
    assert '"x-role"' in headers["Signature-Input"]
    assert verify(request, headers).covered == ("@method", "x-role")


# --- B16: created and expires fit RFC 8941's integer range ---

@pytest.mark.parametrize("field", ["created", "expires"])
@pytest.mark.parametrize("value", [10**15, -1, 2**64])
def test_a_timestamp_outside_the_integer_range_is_a_caller_error(field, value):
    with pytest.raises(ValueError, match="fiki signs one from 0 to 999999999999999"):
        sign(**{field: value})
    args = dict(BASE_ARGS, **{field: value})
    with pytest.raises(ValueError, match="fiki signs one from 0 to 999999999999999"):
        signature_base(method="GET", url=URL, headers={}, covered=["@path"], **args)


@pytest.mark.parametrize("field", ["created", "expires"])
@pytest.mark.parametrize("value", [True, "1700000000", 1.0])
def test_a_timestamp_that_is_not_an_integer_is_a_type_error(field, value):
    with pytest.raises(TypeError, match="is a whole number of seconds"):
        sign(**{field: value})


def test_the_largest_and_smallest_timestamps_are_signed():
    request, headers = sign(created=0, expires=10**15 - 1)
    assert "created=0;expires=999999999999999" in headers["Signature-Input"]
    assert verify(request, headers).aid == KEY.aid


# --- B17: max_age and skew are positive when given ---

@pytest.mark.parametrize("field", ["max_age", "skew"])
@pytest.mark.parametrize("value", [0, -1, -(10**30)])
def test_a_freshness_window_that_is_not_positive_is_a_caller_error(field, value):
    request, headers = sign()
    with pytest.raises(ValueError, match="a freshness window is a positive number"):
        verify(request, headers, **{field: value})
    with pytest.raises(ValueError, match="a freshness window is a positive number"):
        verify_response(expected_keyid=None, minimum=None, status=200, headers={}, **{"max_age": None, field: value})


@pytest.mark.parametrize("field", ["max_age", "skew"])
@pytest.mark.parametrize("value", [True, 1.5, "300"])
def test_a_freshness_window_that_is_not_an_integer_is_a_type_error(field, value):
    request, headers = sign()
    with pytest.raises(TypeError, match="is a whole number of seconds"):
        verify(request, headers, **{field: value})


def test_skew_none_is_not_a_way_to_decline_the_check():
    request, headers = sign()
    with pytest.raises(TypeError, match="skew is a whole number of seconds"):
        verify(request, headers, skew=None)


def test_enormous_windows_neither_overflow_nor_refuse():
    request, headers = sign(expires=10**15 - 1)
    verdict = verify(request, headers, max_age=10**30, skew=10**30, now=10**18)
    assert verdict.aid == KEY.aid


# --- B18: Verdict.keyid is the wire keyid; Verdict.aid is who vouched ---

def test_the_verdict_keyid_is_the_wire_keyid_and_the_aid_is_who_vouched():
    request, headers = sign()
    verdict = verify(request, headers)
    assert (verdict.keyid, verdict.aid) == (keyid_of(KEY), KEY.aid)
    request, headers = sign(keyid="any keyid at all")
    verdict = verify(request, headers, expected_aid=KEY.aid)
    assert (verdict.keyid, verdict.aid) == ("any keyid at all", KEY.aid)


def test_the_verdict_documents_both_fields():
    doc = " ".join(Verdict.__doc__.split())
    assert "exactly as it appeared on the wire" in doc
    assert "None when the signature had none" in doc


# --- B19: both format numbers are exported ---

def test_both_vectors_formats_are_exported():
    """The drivers compare each file with these, so the export is the number this port claims."""
    assert type(VECTORS_FORMAT) is int
    assert type(KERI_VECTORS_FORMAT) is int
    assert {"VECTORS_FORMAT", "KERI_VECTORS_FORMAT"} <= set(EXPORTED)


# --- B20: input bounds, size before shape ---

def test_the_bounds_are_exported_constants():
    assert (MAX_FIELD_BYTES, MAX_DICTIONARY_MEMBERS, MAX_INNER_LIST_ITEMS,
            MAX_PARAMETERS) == (8192, 16, 64, 16)
    assert {"MAX_FIELD_BYTES", "MAX_DICTIONARY_MEMBERS", "MAX_INNER_LIST_ITEMS",
            "MAX_PARAMETERS"} <= set(EXPORTED)


def pad_to(value: str, size: int) -> str:
    """Trailing spaces an RFC 8941 parser discards, so only the size check can refuse it."""
    return value + " " * (size - len(value.encode("utf-8")))


@pytest.mark.parametrize("header, error", [
    ("Signature", MalformedSignature),
    ("Signature-Input", MalformedSignatureInput),
    ("Content-Digest", MalformedDigest),
])
def test_a_field_over_8192_bytes_is_malformed_before_it_is_parsed(header, error):
    request, headers = sign(method="POST", body=BODY)
    headers[header] = pad_to(headers[header], 8193)
    with pytest.raises(error, match="8192"):
        verify(request, headers)


def test_a_field_over_8192_bytes_is_refused_whatever_it_holds():
    request, headers = sign(method="POST", body=BODY)
    headers["Signature-Input"] = "(" * 9000
    with pytest.raises(MalformedSignatureInput, match="8192"):
        verify(request, headers)
    headers["Signature-Input"] = "é" * 4097
    with pytest.raises(MalformedSignatureInput, match="8192"):
        verify(request, headers)


@pytest.mark.parametrize("header, error", [
    ("Signature", MalformedSignature),
    ("Signature-Input", MalformedSignatureInput),
])
@pytest.mark.parametrize("value", ["\ud800", "sig=:\udfff:", "\ud800" * 9000])
def test_a_field_that_cannot_be_encoded_is_malformed(header, error, value):
    request, headers = sign(method="POST", body=BODY)
    headers[header] = value
    with pytest.raises(error):
        verify(request, headers)


@pytest.mark.parametrize("value", ["\ud800", "sha-256=:\udfff:"])
def test_a_content_digest_that_cannot_be_encoded_is_malformed(value):
    asked = Request(method="POST", url=URL, headers={"Content-Digest": value}, body=BODY)
    for covered in (["@status", req("content-digest")], None):
        with pytest.raises(MalformedDigest):
            sign_response(key=KEY, status=200, request=asked, created=AT, covered=covered)
    with pytest.raises(ValueError, match="is not one a verifier would accept"):
        sign(method="POST", body=BODY, headers={"Content-Digest": value})


@pytest.mark.parametrize("header", ["Signature", "Signature-Input", "Content-Digest"])
def test_a_field_of_exactly_8192_bytes_is_read(header):
    request, headers = sign(method="POST", body=BODY)
    headers[header] = pad_to(headers[header], 8192)
    assert verify(request, headers).aid == KEY.aid


def extra_members(n: int) -> str:
    return "".join(f", x{i}=:AAAA:" for i in range(n))


def test_a_dictionary_of_seventeen_members_is_malformed():
    request, headers = sign(method="POST", body=BODY)
    with pytest.raises(MalformedSignature):
        verify(request, dict(headers, Signature=headers["Signature"] + extra_members(16)))
    with pytest.raises(MalformedSignatureInput):
        verify(request, dict(headers, **{
            "Signature-Input": headers["Signature-Input"] + extra_members(16)}))
    with pytest.raises(MalformedDigest):
        verify(*with_digest(content_digest(BODY) + extra_members(16)))


def test_a_dictionary_of_sixteen_members_is_read():
    request, headers = sign(method="POST", body=BODY)
    with pytest.raises(MalformedSignatureLabel):
        verify(request, dict(headers, Signature=headers["Signature"] + extra_members(15)))
    assert verify(*with_digest(content_digest(BODY) + extra_members(15))).aid == KEY.aid


def test_an_inner_list_of_sixty_four_components_is_read_and_sixty_five_is_malformed():
    fields = {f"x-h{i}": str(i) for i in range(62)}
    covered = ["@method", "@path", "@query"] + list(fields)
    request, headers = sign(headers=fields, covered=covered[:64])
    assert len(verify(request, headers).covered) == 64
    request, headers = sign(headers=fields, covered=covered)
    with pytest.raises(MalformedSignatureInput):
        verify(request, headers)


def test_an_inner_list_anywhere_holds_at_most_sixty_four_items():
    with pytest.raises(MalformedDigest):
        verify(*with_digest(content_digest(BODY) + ", x=(" + " ".join(["1"] * 65) + ")"))


def params(n: int) -> str:
    return "".join(f";p{i}" for i in range(n))


def test_an_item_with_seventeen_parameters_is_malformed():
    request, headers = sign(method="POST", body=BODY)
    bad = headers["Signature-Input"].replace('"@path"', '"@path"' + params(17))
    with pytest.raises(MalformedSignatureInput):
        verify(request, dict(headers, **{"Signature-Input": bad}))
    with pytest.raises(MalformedSignature):
        verify(request, dict(headers, Signature=headers["Signature"] + params(17)))
    with pytest.raises(MalformedDigest):
        verify(*with_digest(content_digest(BODY) + params(17)))
    with pytest.raises(MalformedSignatureInput):
        verify(request, dict(headers, **{
            "Signature-Input": headers["Signature-Input"] + params(17)}))


def test_an_item_with_sixteen_parameters_is_read():
    assert verify(*with_digest(content_digest(BODY) + params(16))).aid == KEY.aid


# --- Every message quotes a value it was handed escaped and cut (@524c8qgv, part two) ---

_LONE = "\ud800"
_LONG = "a" * 3000


def _quotable(message: str) -> None:
    """Printable as UTF-8, free of C0, DEL, C1, U+2028 and U+2029, and at most 1024 characters."""
    message.encode("utf-8")
    assert not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F or c in "  "
                   for c in message), ascii(message[:200])
    assert len(message) <= 1024, len(message)


def _long_authority():
    url = "https://" + "a" * 3000 + ".example/x"
    request, headers = sign(url=url, covered=["@authority"])
    return verify(request, headers, authorities={"api.example.com"})


@pytest.mark.parametrize("call, error, fragment", [
    (lambda: sign(covered=['"@pa' + _LONE + 'th"']), UnsupportedComponent, "as a component"),
    (lambda: sign(covered=['"@path";a' + _LONE]), UnsupportedComponent, "as a component"),
    (lambda: sign(covered=['"' + _LONG + '\x85']), UnsupportedComponent, "as a component"),
    (lambda: sign(covered=[_LONG + " x"]), ValueError, "is not a component fiki can name"),
    (lambda: sign(headers={"X-" + _LONE: "a", "x-" + _LONE: "b"}), ValueError,
     "more than once"),
    (lambda: sign(headers={"x-a": 1, "x-" + _LONG: "b"}), TypeError, "both strings"),
    (lambda: sign(headers={1: _LONG}), TypeError, "both strings"),
    (lambda: verify(*sign(), url="https://a" + _LONE + "℀/x"), SignatureMismatch,
     "cannot be read"),
    (lambda: sign(url="https://a\x85℀/x"), ValueError, "cannot be read"),
    (lambda: verify(*sign(), expected_aid=_LONE * 44), MalformedKey, "44 characters"),
    (lambda: verify(*sign(), expected_aid="B" + "A" * 42 + _LONE), MalformedKey,
     "not valid base64url"),
    (lambda: verify(*sign(), expected_aid="B" + "A" * 42 + "\x85"), MalformedKey,
     "not valid base64url"),
    (_long_authority, SignatureMismatch, "does not serve"),
    (lambda: sign(method=_LONG + " "), ValueError, "is not an HTTP method"),
    (lambda: sign(method=_LONE), ValueError, "is not an HTTP method"),
    (lambda: sign(keyid=_LONG + "\n"), ValueError, "outside printable ASCII"),
    (lambda: sign(nonce=_LONE), ValueError, "outside printable ASCII"),
    (lambda: sign(label=_LONG + "A"), ValueError, "is not an RFC 8941 key"),
    (lambda: sign(label=_LONE), ValueError, "is not an RFC 8941 key"),
])
def test_every_message_quotes_what_it_was_handed_escaped_and_cut(call, error, fragment):
    with pytest.raises(error, match=fragment) as caught:
        call()
    _quotable(str(caught.value))

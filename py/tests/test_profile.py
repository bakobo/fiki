"""What the KERI profile of RFC 9421 asks of a verifier that fiki lacked (``this.i`` @7f28p7xk).

The profile (keripy ``.ignored/rfc9421/profile.md``, draft 4) is implemented by keripy, KERIA and
signify-ts, and fiki generates its vectors (@8vwrexxc) because fiki shares no code with any of
them. That only works if fiki implements the profile rather than its own older behaviour where the
two differ, which is what this file pins: method case (@22g0xkr8), every recognized digest,
caller-chosen keyids with an authoritative resolver (@6g9zjsv9), responses bound to their request
with ``req``, the wire-side refusals, an optional minimum covered set, and the profile's section 9
refusal order.

Every refusal is written as a positive assertion about a refusal, because a negative requirement
that is quietly dropped leaves no failing test behind.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from fiki import (
    REQUEST_MINIMUM,
    RESPONSE_MINIMUM,
    Key,
    Request,
    req,
    response_signature_base,
    sign_request,
    sign_response,
    signature_base,
    verify_request,
    verify_response,
)
from fiki.errors import (
    DigestMismatch,
    DuplicateComponent,
    InsufficientCoverage,
    MalformedDigest,
    MalformedKey,
    MalformedSignature,
    MalformedSignatureInput,
    MalformedSignatureLabel,
    MalformedSignatureValue,
    MissingComponent,
    MissingKey,
    MissingSignature,
    SignatureMismatch,
    SignatureTooOld,
    UncoveredBody,
    Unauthenticated,
    UnknownKey,
    UnsupportedComponent,
    UnsupportedSigner,
)
from fiki.messages import content_digest

KEY = Key.from_seed(bytes(range(32)))
OTHER = Key.from_seed(bytes(range(1, 33)))
URL = "https://keria.example.com/identifiers?type=rot"
BODY = b'{"hello": "world"}'
AT = 1700000000


def raw(key: Key) -> bytes:
    return base64.urlsafe_b64decode("A" + key.aid[1:])[1:]


def cesr(code: str, raw_bytes: bytes) -> str:
    """A 44-character qb64 over 32 raw bytes, the arithmetic fiki's own B lens uses."""
    return code + base64.urlsafe_b64encode(b"\x00" + raw_bytes).decode()[1:]


AID = cesr("E", hashlib.sha256(b"a transferable AID").digest())


def sign(**overrides):
    args = dict(key=KEY, method="POST", url=URL, headers={}, body=BODY, created=AT)
    args.update(overrides)
    headers = dict(args["headers"])
    headers.update(sign_request(**args))
    return {"method": args["method"], "url": args["url"], "body": args["body"]}, headers


def verify(request, headers, **overrides):
    args = dict(headers=headers, max_age=None, **request)
    args.update(overrides)
    return verify_request(**args)


def mangle_input(headers, old, new):
    assert old in headers["Signature-Input"]
    headers["Signature-Input"] = headers["Signature-Input"].replace(old, new)
    return headers


# --- @method is the method as sent (@22g0xkr8, RFC 9421 section 2.2.1) ---

def test_the_method_is_not_uppercased_in_the_base():
    base = signature_base(method="post", url=URL, headers={}, covered=["@method"], created=AT,
                          keyid="k")
    assert base.decode().split("\n")[0] == '"@method": post'


def test_a_request_signed_with_a_lowercase_method_does_not_verify_as_uppercase():
    request, headers = sign(method="post")
    assert verify(request, headers).aid == KEY.aid
    request["method"] = "POST"
    with pytest.raises(SignatureMismatch):
        verify(request, headers)


# --- Content-Digest: every recognized member must match (RFC 9530) ---

def test_two_recognized_digests_must_both_match():
    good = content_digest(BODY)
    bad512 = base64.b64encode(hashlib.sha512(b"other").digest()).decode()
    request, headers = sign(headers={"Content-Digest": f"{good}, sha-512=:{bad512}:"})
    with pytest.raises(DigestMismatch):
        verify(request, headers)


def test_two_recognized_digests_that_both_match_verify():
    good512 = base64.b64encode(hashlib.sha512(BODY).digest()).decode()
    request, headers = sign(headers={"Content-Digest": f"sha-512=:{good512}:, {content_digest(BODY)}"})
    assert verify(request, headers).aid == KEY.aid


def test_a_recognized_digest_that_is_not_a_byte_sequence_is_malformed():
    request, headers = sign(headers={"Content-Digest": 'sha-256="not bytes"'})
    with pytest.raises(MalformedDigest):
        verify(request, headers)


def test_an_unparsable_digest_is_malformed_even_when_no_body_was_supplied():
    """Section 9 puts malformed-digest before digest-mismatch."""
    request, headers = sign(headers={"Content-Digest": "(((("})
    request["body"] = None
    with pytest.raises(MalformedDigest):
        verify(request, headers)


# --- caller-chosen keyid and an authoritative resolver (@6g9zjsv9) ---

def test_a_caller_may_sign_with_an_aid_as_the_keyid():
    _, headers = sign(keyid=AID)
    assert f'keyid="{AID}"' in headers["Signature-Input"]


def test_a_resolver_supplies_the_key_for_a_transferable_aid():
    request, headers = sign(keyid=AID)
    verdict = verify(request, headers, resolve={AID: raw(KEY)}.get)
    assert verdict.aid == AID
    assert verdict.keyid == AID


def test_without_a_resolver_the_verdict_still_reports_the_raw_keyid():
    request, headers = sign()
    verdict = verify(request, headers)
    assert verdict.aid == KEY.aid
    assert verdict.keyid == base64.urlsafe_b64encode(raw(KEY)).decode().rstrip("=")


def test_a_keyid_the_resolver_does_not_know_is_an_unknown_key():
    request, headers = sign(keyid=AID)
    with pytest.raises(UnknownKey) as caught:
        verify(request, headers, resolve={}.get)
    assert caught.value.keyid == AID


def test_a_resolver_returning_something_other_than_32_bytes_is_a_malformed_key():
    request, headers = sign(keyid=AID)
    with pytest.raises(MalformedKey):
        verify(request, headers, resolve=lambda keyid: b"short")


def test_a_resolver_may_refuse_a_malformed_keyid_itself():
    def resolve(keyid):
        raise MalformedKey(f"{keyid} is not an AID.", keyid=keyid)

    request, headers = sign(keyid="not-an-aid")
    with pytest.raises(MalformedKey):
        verify(request, headers, resolve=resolve)


def test_a_d_prefixed_keyid_is_never_decoded_as_a_key_when_a_resolver_is_supplied():
    """Profile R1: D... embeds the inception key, so decoding it would undo pre-rotation.

    The request is signed by the key the prefix embeds; the resolver says the current key is a
    different one. Accepting would mean fiki had read the key out of the prefix.
    """
    inception = cesr("D", raw(KEY))
    request, headers = sign(keyid=inception)
    with pytest.raises(SignatureMismatch):
        verify(request, headers, resolve={inception: raw(OTHER)}.get)
    request, headers = sign(key=OTHER, keyid=inception)
    assert verify(request, headers, resolve={inception: raw(OTHER)}.get).aid == inception


def test_a_resolver_with_no_keyid_to_resolve_is_a_missing_key():
    request, headers = sign(keyid=AID)
    mangle_input(headers, f';keyid="{AID}"', "")
    with pytest.raises(MissingKey):
        verify(request, headers, resolve={AID: raw(KEY)}.get)


def test_expected_aid_and_a_resolver_together_are_a_programming_error():
    request, headers = sign()
    with pytest.raises(TypeError):
        verify(request, headers, resolve={}.get, expected_aid=KEY.aid)


# --- component identifiers with parameters ---

def test_req_names_a_request_component_from_a_response():
    assert req("@Method") == '"@method";req'
    assert req("Content-Digest") == '"content-digest";req'


def test_a_caller_may_name_components_in_their_serialized_form():
    request, headers = sign(covered=['"@method"', '"@PATH"', "@query", '"content-digest"'])
    verdict = verify(request, headers)
    assert verdict.covered == ("@method", "@path", "@query", "content-digest")


def test_signing_a_duplicate_component_is_refused():
    with pytest.raises(DuplicateComponent):
        sign(covered=["@method", "@method", "content-digest"])


# --- responses (RFC 9421 section 2.4) ---

REQUEST = Request(method="POST", url=URL, headers={"Content-Digest": content_digest(BODY)},
                  body=BODY)
RESPONSE_BODY = b'{"done": true}'


def respond(**overrides):
    args = dict(key=KEY, status=200, request=REQUEST, headers={}, body=RESPONSE_BODY, created=AT)
    args.update(overrides)
    headers = dict(args["headers"])
    headers.update(sign_response(**args))
    return headers


def check(headers, **overrides):
    args = dict(status=200, headers=headers, body=RESPONSE_BODY, request=REQUEST, max_age=None)
    args.update(overrides)
    return verify_response(**args)


def test_a_signed_response_verifies_and_binds_its_request():
    headers = respond()
    verdict = check(headers)
    assert verdict.aid == KEY.aid
    assert verdict.covered == (
        "@status", '"@method";req', '"@path";req', '"@query";req', "content-digest",
        '"content-digest";req',
    )


def test_the_status_line_is_three_digits():
    base = response_signature_base(status=204, headers={}, covered=["@status"], created=AT,
                                   keyid="k")
    assert base.decode().split("\n")[0] == '"@status": 204'


def test_the_req_lines_carry_the_request_values():
    base = response_signature_base(
        status=200, headers={}, request=REQUEST,
        covered=["@status", req("@method"), req("@path"), req("@query"), req("content-digest")],
        created=AT, keyid="k",
    ).decode().split("\n")
    assert base[1:5] == [
        '"@method";req: POST',
        '"@path";req: /identifiers',
        '"@query";req: ?type=rot',
        f'"content-digest";req: {content_digest(BODY)}',
    ]


def test_an_altered_status_is_refused():
    with pytest.raises(SignatureMismatch):
        check(respond(), status=201)


def test_a_swapped_response_body_is_refused():
    with pytest.raises(DigestMismatch):
        check(respond(), body=b'{"done": false}')


def test_a_response_checked_against_a_different_request_is_refused():
    other = Request(method="POST", url="https://keria.example.com/other?type=rot",
                    headers=REQUEST.headers, body=BODY)
    with pytest.raises(SignatureMismatch):
        check(respond(), request=other)


def test_a_response_with_no_request_covers_only_its_own_components():
    headers = respond(request=None)
    verdict = check(headers, request=None)
    assert verdict.covered == ("@status", "content-digest")


def test_a_bodyless_response_to_a_bodyless_request_covers_no_digest():
    get = Request(method="GET", url=URL)
    headers = respond(request=get, body=None)
    verdict = check(headers, request=get, body=None)
    assert verdict.covered == ("@status", '"@method";req', '"@path";req', '"@query";req')


def test_signing_a_response_body_without_its_digest_is_refused():
    with pytest.raises(UncoveredBody):
        respond(covered=["@status"])


def test_a_req_component_with_no_request_to_read_it_from_is_missing():
    with pytest.raises(MissingComponent):
        respond(request=None, covered=["@status", req("@path"), "content-digest"])


def test_verifying_a_req_component_with_no_request_is_missing():
    with pytest.raises(MissingComponent):
        check(respond(), request=None)


def test_a_req_field_the_request_lacks_is_missing():
    bare = Request(method="POST", url=URL)
    with pytest.raises(MissingComponent):
        respond(request=bare, covered=["@status", req("content-digest"), "content-digest"])


# --- the covered list, as received ---

@pytest.mark.parametrize(
    "covered",
    [
        pytest.param('"@method";sf', id="unsupported-parameter"),
        pytest.param('"@method";req', id="req-in-a-request"),
        pytest.param('"@status"', id="status-in-a-request"),
        pytest.param('"@target-uri"', id="unknown-derived"),
    ],
)
def test_an_unsupported_component_in_a_request_is_refused_not_dropped(covered):
    request, headers = sign()
    mangle_input(headers, '"@method"', covered)
    with pytest.raises(UnsupportedComponent):
        verify(request, headers)


@pytest.mark.parametrize(
    "old,new",
    [
        pytest.param('"@status"', '"@status";req', id="status-with-req"),
        pytest.param('"@path";req', '"@path"', id="request-component-without-req"),
        pytest.param('"@path";req', '"@path";req=?0', id="req-that-is-false"),
        pytest.param('"@path";req', '"@path";req;bs', id="req-plus-another-parameter"),
    ],
)
def test_an_unsupported_component_in_a_response_is_refused(old, new):
    headers = mangle_input(respond(), old, new)
    with pytest.raises(UnsupportedComponent):
        check(headers)


def test_a_duplicate_component_is_refused():
    request, headers = sign()
    mangle_input(headers, '"@path"', '"@path" "@path"')
    with pytest.raises(DuplicateComponent):
        verify(request, headers)


def test_a_duplicate_is_found_whatever_the_parameter_order_and_before_it_is_unsupported():
    headers = mangle_input(respond(), '"content-digest";req',
                           '"content-digest";req;sf "content-digest";sf;req')
    with pytest.raises(DuplicateComponent):
        check(headers)


# --- Signature-Input, as received ---

@pytest.mark.parametrize(
    "old,new",
    [
        pytest.param('"content-digest"', '"Content-Digest"', id="uppercase-field-name"),
        pytest.param(f";created={AT}", f';created={AT};context="x"', id="unknown-parameter"),
        pytest.param(f";created={AT}", ';created="soon"', id="created-not-an-integer"),
        pytest.param(f";created={AT}", ";created=?1", id="created-a-boolean"),
        pytest.param('alg="ed25519"', "alg=ed25519", id="alg-a-token"),
        pytest.param('"@path"', "path", id="component-a-token"),
    ],
)
def test_a_malformed_signature_input_member_is_refused(old, new):
    request, headers = sign()
    mangle_input(headers, old, new)
    with pytest.raises(MalformedSignatureInput):
        verify(request, headers)


def test_a_signature_input_member_that_is_not_an_inner_list_is_refused():
    request, headers = sign()
    headers["Signature-Input"] = 'sig="not a list"'
    with pytest.raises(MalformedSignatureInput):
        verify(request, headers)


def test_two_labels_in_the_signature_header_are_malformed():
    request, headers = sign()
    value = headers["Signature"].split("=", 1)[1]
    headers["Signature"] = f"{headers['Signature']}, other={value}"
    with pytest.raises(MalformedSignatureLabel):
        verify(request, headers)


def test_a_signature_that_is_not_64_bytes_is_a_malformed_value():
    request, headers = sign()
    headers["Signature"] = "sig=:" + base64.b64encode(bytes(32)).decode() + ":"
    with pytest.raises(MalformedSignatureValue):
        verify(request, headers)


# --- the section 9 order ---

def test_an_unsigned_message_is_missing_its_signature_first():
    request, headers = sign()
    del headers["Signature"], headers["Signature-Input"]
    with pytest.raises(MissingSignature):
        verify(request, headers)


def test_an_unparsable_signature_is_reported_before_an_unparsable_input():
    request, headers = sign()
    headers["Signature"] = "(((("
    headers["Signature-Input"] = "(((("
    with pytest.raises(MalformedSignature):
        verify(request, headers)


def test_a_malformed_key_is_reported_before_an_unsupported_algorithm():
    request, headers = sign()
    keyid = headers["Signature-Input"].split('keyid="')[1].split('"')[0]
    mangle_input(headers, keyid, "not-a-key")
    mangle_input(headers, 'alg="ed25519"', 'alg="rsa-pss-sha512"')
    with pytest.raises(MalformedKey):
        verify(request, headers)


def test_staleness_is_reported_before_expiry():
    request, headers = sign(expires=AT + 10)
    with pytest.raises(SignatureTooOld):
        verify(request, headers, max_age=300, skew=60, now=AT + 1000)


# --- the minimum covered set (profile section 3) ---

def test_the_minimum_sets_are_the_profiles():
    assert REQUEST_MINIMUM == ("@method", "@path", "@query")
    assert RESPONSE_MINIMUM == ("@status", req("@method"), req("@path"), req("@query"))


def test_a_request_covering_the_minimum_verifies():
    request, headers = sign()
    assert verify(request, headers, minimum=REQUEST_MINIMUM).aid == KEY.aid


def test_a_request_covering_less_than_the_minimum_is_refused_even_though_it_verifies():
    request, headers = sign(covered=["@method", "@path", "content-digest"])
    assert verify(request, headers).aid == KEY.aid
    with pytest.raises(InsufficientCoverage) as caught:
        verify(request, headers, minimum=REQUEST_MINIMUM)
    assert caught.value.component == "@query"


def test_a_minimum_may_be_named_in_serialized_form():
    request, headers = sign()
    minimum = ['"@method"', '"@PATH"', '"@query"']
    assert verify(request, headers, minimum=minimum).aid == KEY.aid


@pytest.mark.parametrize(
    "extra,body",
    [
        pytest.param({"Content-Length": "18"}, None, id="content-length-above-zero"),
        pytest.param({"Content-Length": "many"}, None, id="content-length-unreadable"),
        pytest.param({"Transfer-Encoding": "chunked"}, None, id="any-transfer-encoding"),
        pytest.param({}, BODY, id="a-body-that-arrived-anyway"),
    ],
)
def test_a_body_without_a_covered_digest_is_insufficient_coverage(extra, body):
    request, headers = sign(body=None, headers=extra)
    request["body"] = body
    with pytest.raises(InsufficientCoverage) as caught:
        verify(request, headers, minimum=REQUEST_MINIMUM)
    assert caught.value.component == "content-digest"


def test_a_bodyless_request_needs_no_digest_under_a_minimum():
    request, headers = sign(method="GET", body=None)
    assert verify(request, headers, minimum=REQUEST_MINIMUM).aid == KEY.aid


def test_a_zero_content_length_is_no_body():
    request, headers = sign(body=None, headers={"Content-Length": "0"})
    request["body"] = b""
    assert verify(request, headers, minimum=REQUEST_MINIMUM).aid == KEY.aid


def test_insufficient_coverage_is_reported_before_the_key():
    request, headers = sign(covered=["@method", "@path", "content-digest"])
    keyid = headers["Signature-Input"].split('keyid="')[1].split('"')[0]
    mangle_input(headers, keyid, "not-a-key")
    with pytest.raises(InsufficientCoverage):
        verify(request, headers, minimum=REQUEST_MINIMUM)


def test_a_response_covering_the_minimum_verifies():
    assert check(respond(), minimum=RESPONSE_MINIMUM).aid == KEY.aid


def test_a_response_missing_a_req_component_is_refused():
    headers = respond(covered=["@status", req("@method"), req("@query"), "content-digest",
                               req("content-digest")])
    with pytest.raises(InsufficientCoverage) as caught:
        check(headers, minimum=RESPONSE_MINIMUM)
    assert caught.value.component == '"@path";req'


def test_a_response_body_without_its_digest_is_refused():
    headers = respond(body=None, headers={"Content-Length": "14"})
    with pytest.raises(InsufficientCoverage) as caught:
        check(headers, body=RESPONSE_BODY, minimum=RESPONSE_MINIMUM)
    assert caught.value.component == "content-digest"


def test_a_response_to_a_request_with_a_body_must_cover_the_requests_digest():
    headers = respond(covered=list(RESPONSE_MINIMUM) + ["content-digest"])
    with pytest.raises(InsufficientCoverage) as caught:
        check(headers, minimum=RESPONSE_MINIMUM)
    assert caught.value.component == '"content-digest";req'


def test_a_response_judges_its_requests_body_by_content_not_headers():
    """Profile section 3 (version 1): both sides hold the whole request by the time a response
    is signed or verified, so the request's headers do not count (@7p9s3g9k)."""
    chunked = Request(method="POST", url=URL, headers={"Transfer-Encoding": "chunked",
                                                        "Content-Digest": content_digest(BODY)})
    headers = respond(request=chunked, covered=list(RESPONSE_MINIMUM) + ["content-digest"])
    assert check(headers, request=chunked, minimum=RESPONSE_MINIMUM).aid == KEY.aid


# --- the first review's findings and the profile's draft 6 (@2f227n4r) ---

def test_a_default_response_does_not_bind_a_request_body_only_its_headers_announce():
    """By content alone (@7p9s3g9k): a Request handed over without its body binds no digest."""
    asked = Request(method="POST", url=URL, headers={"Content-Length": "18",
                                                     "Content-Digest": content_digest(BODY)})
    headers = respond(request=asked)
    verdict = check(headers, request=asked, minimum=RESPONSE_MINIMUM)
    assert req("content-digest") not in verdict.covered


def test_a_default_response_binds_the_digest_of_a_request_with_content():
    asked = Request(method="POST", url=URL, headers={"Content-Digest": content_digest(BODY)},
                    body=BODY)
    headers = respond(request=asked)
    assert req("content-digest") in check(headers, request=asked, minimum=RESPONSE_MINIMUM).covered


def test_a_default_response_to_a_body_with_no_digest_to_bind_is_refused_at_signing():
    """The review's finding 1: the signer must not produce what the verifier's minimum refuses."""
    asked = Request(method="POST", url=URL, body=BODY)
    with pytest.raises(UncoveredBody):
        respond(request=asked)


def test_a_missing_keyid_is_reported_before_the_covered_list():
    request, headers = sign(covered=["@method", "content-digest"], keyid=AID)
    mangle_input(headers, f';keyid="{AID}"', "")
    with pytest.raises(MissingKey):
        verify(request, headers, resolve={AID: raw(KEY)}.get, minimum=REQUEST_MINIMUM)


def test_a_missing_keyid_is_reported_before_the_labels():
    request, headers = sign(keyid=AID)
    mangle_input(headers, f';keyid="{AID}"', "")
    value = headers["Signature-Input"].split("=", 1)[1]
    headers["Signature-Input"] += f", other={value}"
    with pytest.raises(MissingKey):
        verify(request, headers, resolve={AID: raw(KEY)}.get)


def test_a_missing_keyid_is_fine_when_the_verifier_names_the_key():
    request, headers = sign()
    keyid = headers["Signature-Input"].split('keyid="')[1].split('"')[0]
    mangle_input(headers, f';keyid="{keyid}"', "")
    with pytest.raises(SignatureMismatch):
        verify(request, headers, expected_aid=KEY.aid)


def test_a_head_response_carrying_a_content_length_has_no_body():
    """The review's finding 4: a response's body is its content, never its Content-Length."""
    head = Request(method="HEAD", url=URL)
    headers = respond(request=head, body=None, headers={"Content-Length": "898"})
    verdict = check(headers, request=head, body=None, minimum=RESPONSE_MINIMUM)
    assert "content-digest" not in verdict.covered


@pytest.mark.parametrize("length", ["-5", "18 bytes", "+3"])
def test_a_content_length_that_is_not_a_plain_decimal_counts_as_a_body(length):
    request, headers = sign(body=None, headers={"Content-Length": length})
    with pytest.raises(InsufficientCoverage):
        verify(request, headers, minimum=REQUEST_MINIMUM)


def test_a_malformed_component_spec_is_a_fiki_error():
    with pytest.raises(UnsupportedComponent):
        sign(covered=['"@path'])


def test_a_signer_given_a_minimum_refuses_a_covered_list_below_it():
    with pytest.raises(InsufficientCoverage):
        sign(body=None, covered=["@method", "@path"], minimum=REQUEST_MINIMUM)
    request, headers = sign(minimum=REQUEST_MINIMUM)
    assert verify(request, headers, minimum=REQUEST_MINIMUM).aid == KEY.aid


def test_a_signer_given_a_minimum_refuses_a_body_it_would_not_cover():
    with pytest.raises(InsufficientCoverage):
        sign(body=None, headers={"Transfer-Encoding": "chunked"}, minimum=REQUEST_MINIMUM)


def test_a_response_signer_given_a_minimum_refuses_a_covered_list_below_it():
    with pytest.raises(InsufficientCoverage):
        respond(covered=["@status", "content-digest"], minimum=RESPONSE_MINIMUM)
    assert check(respond(minimum=RESPONSE_MINIMUM), minimum=RESPONSE_MINIMUM).aid == KEY.aid


def test_a_signer_refuses_an_unsupported_component_parameter():
    with pytest.raises(UnsupportedComponent):
        sign(covered=['"@method";sf', "@path", "content-digest"])


def test_a_response_from_an_aid_other_than_the_expected_one_is_an_unknown_key():
    headers = respond(keyid=AID)
    resolve = {AID: raw(KEY)}.get
    assert check(headers, resolve=resolve, expected_keyid=AID).keyid == AID
    with pytest.raises(UnknownKey):
        check(headers, resolve=resolve, expected_keyid=cesr("E", bytes(32)))


def test_a_covered_authority_outside_the_served_set_is_a_signature_mismatch():
    request, headers = sign(url="/identifiers", headers={"Host": "other.example.com"})
    assert verify(request, headers, authorities={"other.example.com"}).aid == KEY.aid
    with pytest.raises(SignatureMismatch):
        verify(request, headers, authorities={"keria.example.com"})


def test_served_authorities_do_not_apply_when_authority_is_not_covered():
    request, headers = sign(covered=["@method", "@path", "@query", "content-digest"])
    assert verify(request, headers, authorities={"elsewhere.example.com"}).aid == KEY.aid


def test_an_unsigned_401_is_unauthenticated_before_anything_else():
    with pytest.raises(Unauthenticated):
        check({"Content-Type": "application/json"}, status=401, body=b'{"title": "no"}')


def test_an_unsigned_200_is_missing_its_signature():
    with pytest.raises(MissingSignature):
        check({}, status=200)


def test_a_signed_401_is_verified_like_any_other_response():
    headers = respond(status=401)
    assert check(headers, status=401).aid == KEY.aid


def test_a_resolver_may_refuse_a_key_state_with_no_single_signer():
    def resolve(keyid):
        raise UnsupportedSigner(f"{keyid} has no single effective signer.", keyid=keyid)

    request, headers = sign(keyid=AID)
    with pytest.raises(UnsupportedSigner):
        verify(request, headers, resolve=resolve)


@pytest.mark.parametrize("value", ["café", "two\nlines", "bell\x07"])
def test_a_base_that_cannot_be_built_is_a_signature_mismatch(value):
    request, headers = sign(headers={"X-Note": "plain"},
                            covered=["@method", "@path", "@query", "x-note", "content-digest"])
    headers["X-Note"] = value
    with pytest.raises(SignatureMismatch):
        verify(request, headers)
    with pytest.raises(SignatureMismatch):
        signature_base(method="GET", url=URL, headers={"X-Note": value}, covered=["x-note"],
                       created=AT, keyid="k")


def test_a_tab_in_a_field_value_still_builds():
    request, headers = sign(headers={"X-Note": "a\tb"},
                            covered=["@method", "@path", "@query", "x-note", "content-digest"])
    assert verify(request, headers).aid == KEY.aid


def test_a_signature_member_that_is_not_a_byte_sequence_is_found_before_the_labels():
    request, headers = sign()
    value = headers["Signature-Input"].split("=", 1)[1]
    headers["Signature-Input"] += f", other={value}"
    headers["Signature"] = 'sig="not bytes"'
    with pytest.raises(MalformedSignatureValue):
        verify(request, headers)


def test_an_empty_keyid_is_a_missing_key():
    request, headers = sign(keyid="")
    with pytest.raises(MissingKey):
        verify(request, headers, resolve={}.get)


# --- @status is a three-digit status code (bakobo/fiki#4 review) ---

@pytest.mark.parametrize("status", [99, 1000, -200, True, "200"])
def test_a_status_that_is_not_three_digits_has_no_status_line(status):
    with pytest.raises(MissingComponent) as caught:
        response_signature_base(status=status, headers={}, covered=["@status"], created=AT,
                                keyid="k")
    assert caught.value.component == "@status"
    with pytest.raises(MissingComponent):
        check(respond(), status=status)


@pytest.mark.parametrize("status", [100, 999])
def test_the_status_range_is_inclusive(status):
    base = response_signature_base(status=status, headers={}, covered=["@status"], created=AT,
                                   keyid="k")
    assert base.decode().split("\n")[0] == f'"@status": {status}'


# --- created is required under a minimum (@7p9s3g9k) ---

def _without_created():
    request, headers = sign()
    signed_input = headers["Signature-Input"]
    headers["Signature-Input"] = signed_input.replace(f";created={AT}", "")
    return request, headers


def test_a_minimum_requires_created_as_part_of_signature_input():
    request, headers = _without_created()
    with pytest.raises(MalformedSignatureInput):
        verify(request, headers, minimum=REQUEST_MINIMUM)


def test_a_missing_created_under_a_minimum_is_reported_before_the_covered_list():
    request, headers = _without_created()
    mangle_input(headers, '"@path"', '"@path" "@path"')
    with pytest.raises(MalformedSignatureInput):
        verify(request, headers, minimum=REQUEST_MINIMUM)


def test_without_a_minimum_created_stays_optional_as_rfc_9421_makes_it():
    """The generic path is unchanged: the missing created surfaces only as the signature it
    breaks, because nothing else here asked for one."""
    request, headers = _without_created()
    with pytest.raises(SignatureMismatch):
        verify(request, headers)


# --- a covered "content-digest";req is recomputed over the request body (bakobo/fiki#4) ---

def test_a_swapped_request_body_is_refused_when_the_response_binds_its_digest():
    swapped = Request(method=REQUEST.method, url=REQUEST.url, headers=REQUEST.headers,
                      body=b'{"hello": "mallory"}')
    with pytest.raises(DigestMismatch):
        check(respond(), request=swapped)


def test_an_unreadable_request_digest_is_malformed_when_the_response_binds_it():
    covered = ["@status", req("@method"), req("@path"), req("@query"), req("content-digest"),
               "content-digest"]
    unread = Request(method="POST", url=URL, headers={"Content-Digest": "(((("})
    headers = respond(request=unread, covered=covered)
    odd = Request(method="POST", url=URL, headers={"Content-Digest": "(((("}, body=BODY)
    with pytest.raises(MalformedDigest):
        check(headers, request=odd)


def test_a_signer_will_not_bind_a_request_digest_its_body_contradicts():
    """The verifier's check, run first by the signer: a server does not vouch for a request
    digest that the body it was handed does not match (@2f227n4r's principle)."""
    swapped = Request(method=REQUEST.method, url=REQUEST.url, headers=REQUEST.headers,
                      body=b'{"hello": "mallory"}')
    with pytest.raises(DigestMismatch):
        respond(request=swapped)
    odd = Request(method="POST", url=URL, headers={"Content-Digest": "(((("}, body=BODY)
    with pytest.raises(MalformedDigest):
        respond(request=odd)


def test_a_request_handed_over_without_its_body_is_not_recomputed():
    bodiless = Request(method=REQUEST.method, url=REQUEST.url, headers=REQUEST.headers)
    assert check(respond(), request=bodiless).aid == KEY.aid


# --- a supplied minimum can only add to the profile's (bakobo/fiki#4) ---

@pytest.mark.parametrize("minimum", [(), ["@method", "@path"], [req("@method")]])
def test_a_request_minimum_below_the_profiles_is_a_caller_error(minimum):
    request, headers = sign()
    with pytest.raises(ValueError):
        verify(request, headers, minimum=minimum)
    with pytest.raises(ValueError):
        sign(minimum=minimum)


@pytest.mark.parametrize("minimum", [(), REQUEST_MINIMUM, ["@status", req("@method")]])
def test_a_response_minimum_below_the_profiles_is_a_caller_error(minimum):
    with pytest.raises(ValueError):
        check(respond(), minimum=minimum)
    with pytest.raises(ValueError):
        respond(minimum=minimum)


def test_a_minimum_may_add_requirements_beyond_the_profiles():
    request, headers = sign()
    assert verify(request, headers, minimum=list(REQUEST_MINIMUM) + ["@authority"]).aid == KEY.aid
    with pytest.raises(InsufficientCoverage):
        verify(*sign(covered=list(REQUEST_MINIMUM) + ["content-digest"]),
               minimum=list(REQUEST_MINIMUM) + ["@authority"])


# --- an AID-shaped keyid is spelled canonically before any resolver sees it (fiki#4, Codex #1) ---

@pytest.mark.parametrize("code", ["B", "D", "E"])
def test_a_padding_bit_alias_is_malformed_even_through_a_resolver(code):
    from test_keys import padding_bit_alias

    alias = padding_bit_alias(cesr(code, raw(KEY)))
    request, headers = sign(keyid=alias)
    with pytest.raises(MalformedKey):
        verify(request, headers, resolve=lambda keyid: raw(KEY))
    with pytest.raises(MalformedKey):
        verify(request, headers, resolve=lambda keyid: None)


def test_an_aid_shaped_keyid_outside_the_alphabet_is_malformed_through_a_resolver():
    request, headers = sign(keyid="E" + "!" * 43)
    with pytest.raises(MalformedKey):
        verify(request, headers, resolve=lambda keyid: raw(KEY))


def test_a_canonical_aid_still_reaches_the_resolver():
    request, headers = sign(keyid=AID)
    assert verify(request, headers, resolve={AID: raw(KEY)}.get).aid == AID

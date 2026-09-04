"""The high-level sign and verify surface, and the whole of @2hwvpm42.

The refusals are the point of this file. fiki exists because heti's KERI dialect leaves the query
string, the host, and the body uncovered and structurally cannot cover them; a fiki that merely
*could* cover them, while defaulting to something narrower or accepting a request whose digest
nobody checked, would have moved the problem rather than solved it.

So the tamper cases below are the load-bearing rows: each one changes something an attacker would
change and asserts that verification refuses. A negative requirement leaves no failing test behind
when it is quietly dropped (cc ledger #22), so each is written as a positive assertion about a
refusal.
"""

from __future__ import annotations

import base64

import pytest

from fiki import DEFAULT_COVERED, Key, sign_request, verify_request, verifying_key
from fiki.messages import content_digest
from fiki.errors import (
    DigestMismatch,
    MalformedDigest,
    MalformedKey,
    MalformedSignature,
    MalformedSignatureInput,
    MalformedSignatureLabel,
    MalformedSignatureValue,
    MissingKey,
    MissingSignature,
    MissingSignatureInput,
    MissingSignatureLabel,
    SignatureExpired,
    SignatureMismatch,
    SignatureTooOld,
    UncoveredBody,
    UnsupportedAlgorithm,
)

KEY = Key.from_seed(bytes(range(32)))
URL = "https://api.example.com/things?limit=1&sort=name"
BODY = b'{"hello": "world"}'


def signed(**overrides):
    args = dict(key=KEY, method="POST", url=URL, headers={}, body=BODY)
    args.update(overrides)
    request = {k: args[k] for k in ("method", "url", "body")}
    headers = dict(args["headers"])
    headers.update(sign_request(**args))
    return request, headers


def test_a_signed_request_verifies_and_names_the_signer():
    request, headers = signed()
    verdict = verify_request(headers=headers, max_age=None, **request)
    assert verdict.aid == KEY.aid


def test_the_default_covered_set_binds_method_authority_path_and_query():
    request, headers = signed()
    verdict = verify_request(headers=headers, max_age=None, **request)
    assert set(DEFAULT_COVERED) <= set(verdict.covered)


def test_the_keyid_carries_the_raw_key_rather_than_the_aid():
    """@7xrx5evg — heti's vanilla dialect decodes keyid as 32 raw bytes, so fiki emits that form."""
    _, headers = signed()
    keyid = headers["Signature-Input"].split('keyid="')[1].split('"')[0]
    assert len(keyid) == 43
    assert base64.urlsafe_b64decode(keyid + "=") == verifying_key(KEY.aid).public_bytes_raw()


def test_a_body_is_digested_and_the_digest_is_covered():
    _, headers = signed()
    assert "Content-Digest" in headers
    request, hdrs = signed()
    assert "content-digest" in verify_request(headers=hdrs, max_age=None, **request).covered


def test_signing_a_body_with_a_covered_set_that_excludes_the_digest_is_refused():
    """The refusal @2hwvpm42 turns on. A warning here would be read by nobody."""
    with pytest.raises(UncoveredBody):
        sign_request(key=KEY, method="POST", url=URL, headers={}, body=BODY,
                     covered=("@method", "@path"))


def test_a_bodyless_request_needs_no_digest():
    request, headers = signed(body=None)
    assert "Content-Digest" not in headers
    assert verify_request(headers=headers, max_age=None, **request).aid == KEY.aid


# --- the tampering that heti's KERI dialect cannot detect ---

def test_a_rewritten_query_string_is_refused():
    """The headline case: heti's KERI dialect cannot see this, because @path stops at the "?"."""
    request, headers = signed()
    request["url"] = "https://api.example.com/things?limit=1000000&sort=name"
    with pytest.raises(SignatureMismatch):
        verify_request(headers=headers, max_age=None, **request)


def test_a_rewritten_host_is_refused():
    request, headers = signed()
    request["url"] = "https://evil.example.com/things?limit=1&sort=name"
    with pytest.raises(SignatureMismatch):
        verify_request(headers=headers, max_age=None, **request)


def test_a_swapped_body_is_refused():
    request, headers = signed()
    request["body"] = b'{"hello": "goodbye"}'
    with pytest.raises(DigestMismatch):
        verify_request(headers=headers, max_age=None, **request)


def test_a_swapped_body_with_a_matching_digest_is_still_refused():
    """Because the digest header is itself covered, re-digesting does not rescue the tamper."""
    import hashlib

    request, headers = signed()
    request["body"] = b'{"hello": "goodbye"}'
    digest = base64.b64encode(hashlib.sha256(request["body"]).digest()).decode()
    headers["Content-Digest"] = f"sha-256=:{digest}:"
    with pytest.raises(SignatureMismatch):
        verify_request(headers=headers, max_age=None, **request)


def test_a_covered_digest_with_no_body_to_check_it_against_is_refused():
    """Fail closed: a verifier that cannot check the digest has not checked the body."""
    request, headers = signed()
    request["body"] = None
    with pytest.raises(DigestMismatch):
        verify_request(headers=headers, max_age=None, **request)


def test_a_rewritten_method_is_refused():
    request, headers = signed()
    request["method"] = "DELETE"
    with pytest.raises(SignatureMismatch):
        verify_request(headers=headers, max_age=None, **request)


def test_a_signature_from_a_different_key_is_refused():
    request, headers = signed()
    other = Key.from_seed(bytes(range(1, 33)))
    _, theirs = signed(key=other)
    headers["Signature"] = theirs["Signature"]
    with pytest.raises(SignatureMismatch):
        verify_request(headers=headers, max_age=None, **request)


# --- preregistration, which is the case an AID exists for ---

def test_an_expected_aid_is_authoritative_over_the_inline_keyid():
    request, headers = signed()
    assert verify_request(headers=headers, expected_aid=KEY.aid, max_age=None, **request).aid == KEY.aid


def test_a_request_signed_by_someone_other_than_the_expected_aid_is_refused():
    request, headers = signed()
    stranger = Key.from_seed(bytes(range(1, 33))).aid
    with pytest.raises(SignatureMismatch):
        verify_request(headers=headers, expected_aid=stranger, max_age=None, **request)


# --- malformed input ---

@pytest.mark.parametrize(
    "mangle,expected",
    [
        pytest.param(lambda h: h.pop("Signature"), MissingSignature, id="no-signature"),
        pytest.param(lambda h: h.pop("Signature-Input"), MissingSignatureInput,
                     id="no-signature-input"),
        pytest.param(lambda h: h.update({"Signature-Input": "not a dictionary («"}),
                     MalformedSignatureInput, id="unparsable-input"),
        pytest.param(lambda h: h.update({"Signature": "sig=:not-base64!:"}), MalformedSignature,
                     id="unparsable-signature"),
    ],
)
def test_malformed_signature_headers_are_refused(mangle, expected):
    """Each header names its own condition, so a sender can be told which one to fix.

    The granularity is a contract rather than a preference: heti maps these classes one to one
    onto codes it already publishes, so folding two of them together here would narrow heti's
    error surface the moment it delegates (@8zw78n0v).
    """
    request, headers = signed()
    mangle(headers)
    with pytest.raises(expected):
        verify_request(headers=headers, max_age=None, **request)


def test_two_signature_labels_are_refused():
    """One label, so there is never a question of which signature the verdict is about."""
    request, headers = signed()
    label, rest = headers["Signature-Input"].split("=", 1)
    headers["Signature-Input"] = f"{headers['Signature-Input']},other={rest}"
    with pytest.raises(MalformedSignatureLabel):
        verify_request(headers=headers, max_age=None, **request)


def test_an_algorithm_other_than_ed25519_is_refused():
    request, headers = signed()
    headers["Signature-Input"] = headers["Signature-Input"] + ';alg="rsa-pss-sha512"'
    with pytest.raises(UnsupportedAlgorithm):
        verify_request(headers=headers, max_age=None, **request)


# --- paths a caller reaches by driving fiki rather than accepting its defaults ---

def test_an_explicit_covered_set_that_includes_the_digest_signs_a_body():
    """The other half of @2hwvpm42's refusal: naming content-digest yourself is fine."""
    request, headers = signed(covered=("@method", "@path", "content-digest"))
    assert "Content-Digest" in headers
    assert verify_request(headers=headers, max_age=None, **request).aid == KEY.aid


def test_a_caller_supplied_content_digest_is_used_rather_than_recomputed():
    """A caller that already hashed its body should not be made to hash it twice."""
    supplied = {"Content-Digest": content_digest(BODY)}
    request, headers = signed(headers=supplied)
    assert headers["Content-Digest"] == supplied["Content-Digest"]
    assert verify_request(headers=headers, max_age=None, **request).aid == KEY.aid


def test_a_content_digest_naming_an_unknown_algorithm_alongside_a_known_one_verifies():
    """RFC 9530 allows several digests; fiki checks the first it can compute."""
    supplied = {"Content-Digest": f"sha-1=:AAAA:, {content_digest(BODY)}"}
    request, headers = signed(headers=supplied)
    assert verify_request(headers=headers, max_age=None, **request).aid == KEY.aid


def test_a_content_digest_naming_only_algorithms_fiki_cannot_compute_is_refused():
    """Fail closed: an uncheckable digest is an unchecked body, not a checked one."""
    request, headers = signed(headers={"Content-Digest": "sha-1=:AAAA:"})
    with pytest.raises(MalformedDigest):
        verify_request(headers=headers, max_age=None, **request)


# --- more malformed input ---

def test_a_signature_labelled_differently_from_its_input_is_refused():
    request, headers = signed()
    headers["Signature"] = "other=" + headers["Signature"].split("=", 1)[1]
    with pytest.raises(MissingSignatureLabel):
        verify_request(headers=headers, max_age=None, **request)


def test_a_signature_that_is_not_a_byte_sequence_is_refused():
    request, headers = signed()
    headers["Signature"] = 'sig="this is a string, not a byte sequence"'
    with pytest.raises(MalformedSignatureValue):
        verify_request(headers=headers, max_age=None, **request)


def test_a_signature_with_no_keyid_and_no_expected_aid_is_refused():
    request, headers = signed()
    inputs = headers["Signature-Input"]
    headers["Signature-Input"] = inputs.split(";keyid=")[0] + ";alg=\"ed25519\""
    with pytest.raises(MissingKey):
        verify_request(headers=headers, max_age=None, **request)


def test_a_keyid_that_is_not_a_key_is_refused():
    request, headers = signed()
    keyid = headers["Signature-Input"].split('keyid="')[1].split('"')[0]
    headers["Signature-Input"] = headers["Signature-Input"].replace(keyid, "not-a-key")
    with pytest.raises(MalformedKey):
        verify_request(headers=headers, max_age=None, **request)


# --- freshness (``this.i`` @67shl6c5) ---

SIGNED_AT = 1700000000


def fresh(**overrides):
    args = dict(created=SIGNED_AT)
    args.update(overrides)
    return signed(**args)


def test_max_age_is_a_required_decision_rather_than_a_default():
    """Both defaults are wrong, so fiki refuses to pick one.

    A value would guess at somebody else's clock skew and replay window; None would reproduce the
    silent skip this whole behaviour exists to remove. A caller writes their tolerance, or writes
    None, and either way the choice is visible at the call site.
    """
    request, headers = fresh()
    with pytest.raises(TypeError):
        verify_request(headers=headers, **request)


def test_a_signature_within_max_age_verifies():
    request, headers = fresh()
    verdict = verify_request(headers=headers, max_age=300, now=SIGNED_AT + 299, **request)
    assert verdict.aid == KEY.aid


def test_a_signature_older_than_max_age_is_refused():
    request, headers = fresh()
    with pytest.raises(SignatureTooOld):
        verify_request(headers=headers, max_age=300, now=SIGNED_AT + 400, **request)


def test_max_age_none_declines_the_check_explicitly():
    """The escape hatch is a written decision, not an omission."""
    request, headers = fresh()
    assert verify_request(
        headers=headers, max_age=None, now=SIGNED_AT + 10**6, **request
    ).aid == KEY.aid


def test_clock_skew_is_tolerated_so_a_second_of_disagreement_is_not_an_attack():
    request, headers = fresh()
    assert verify_request(
        headers=headers, max_age=300, now=SIGNED_AT + 303, **request
    ).aid == KEY.aid


def test_the_skew_allowance_is_adjustable():
    request, headers = fresh()
    with pytest.raises(SignatureTooOld):
        verify_request(headers=headers, max_age=300, skew=0, now=SIGNED_AT + 301, **request)


def test_a_signature_created_in_the_future_beyond_skew_is_refused():
    """A created in the future is either a broken clock or somebody buying themselves time."""
    request, headers = fresh()
    with pytest.raises(SignatureTooOld):
        verify_request(headers=headers, max_age=300, now=SIGNED_AT - 60, **request)


# --- expires: the signer's own declaration, honoured without being asked ---

def test_expires_is_enforced_even_when_max_age_is_none():
    """The asymmetry that matters: expires is the SIGNER's assertion, max_age is the verifier's.

    Requiring a verifier to opt in to honouring a signer's own expiry would invert who is
    asserting what, and accepting an expires without checking it is the defect ~3qdj named.
    """
    request, headers = fresh(expires=SIGNED_AT + 60)
    with pytest.raises(SignatureExpired):
        verify_request(headers=headers, max_age=None, now=SIGNED_AT + 61 + 5, **request)


def test_a_signature_before_its_expiry_verifies():
    request, headers = fresh(expires=SIGNED_AT + 60)
    assert verify_request(
        headers=headers, max_age=None, now=SIGNED_AT + 30, **request
    ).aid == KEY.aid


def test_a_request_declaring_no_freshness_at_all_verifies_without_reading_a_clock():
    """Determinism is what keeps @5gf6r08f's vectors byte-exact; the clock is read only on demand."""
    request, headers = fresh()
    assert verify_request(headers=headers, max_age=None, **request).aid == KEY.aid


def test_a_signature_with_no_created_cannot_be_aged_and_is_refused():
    """Fail closed: an age that cannot be computed is not an age within the limit.

    RFC 9421 makes created optional, so a foreign signer may legitimately omit it — fiki's own
    never does, and `signature_base` will not build one without it. The signature has to be
    genuinely made this way rather than tampered into shape, because freshness is checked after
    verification and a doctored Signature-Input simply fails the signature instead.
    """
    import http_sfv

    from fiki.base import component_lines

    covered = ["@method", "@path"]
    inner = http_sfv.InnerList([http_sfv.Item(c) for c in covered])
    inner.params["keyid"] = base64.urlsafe_b64encode(
        verifying_key(KEY.aid).public_bytes_raw()
    ).decode().rstrip("=")
    lines = component_lines(method="GET", url="/a", headers={}, covered=covered)
    lines.append(f'"@signature-params": {inner}')
    signature = KEY.sign("\n".join(lines).encode("utf-8"))
    headers = {
        "Signature-Input": f"sig={inner}",
        "Signature": "sig=:" + base64.b64encode(signature).decode() + ":",
    }

    assert verify_request(method="GET", url="/a", headers=headers, max_age=None).aid == KEY.aid
    with pytest.raises(SignatureTooOld):
        verify_request(method="GET", url="/a", headers=headers, max_age=300, now=SIGNED_AT)

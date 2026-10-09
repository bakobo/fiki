"""The httpwg structured-field-tests corpus, run against fiki-py's RFC 8941 parsing (``this.i`` @7fexwu3s).

The corpus is written by RFC 8941's authors and is independent of fiki, so where fiki-py disagrees
with it fiki-py is wrong, except where a recorded fiki decision says otherwise. Those exceptions are
the only ones, and each is named below: RFC 9651's Dates and Display Strings are refused
(@7vdhfv3q), fiki's input bounds are refused (@5zrf8gjk), a byte sequence whose padding is
missing, partial or excessive is refused (@2g4xxev9), and an empty dictionary is refused (review
B7, pinned by vectors/refusals.json signature-header-of-spaces).

Entry points. A dictionary case runs through ``messages._parse``, the bounded entry point
``verify_request`` reads Signature-Input through: it measures MAX_FIELD_BYTES, parses with
http_sfv, counts MAX_DICTIONARY_MEMBERS, MAX_INNER_LIST_ITEMS and MAX_PARAMETERS, and refuses what
RFC 8941 does not allow. A list or an item case runs through the same function told to parse that
structure instead, so every bound applies there too, with a list's members counted against
MAX_DICTIONARY_MEMBERS as the other five ports count them.
"""

from __future__ import annotations

import base64
import json
from decimal import Decimal
from pathlib import Path

import http_sfv
import pytest

from fiki import (MAX_DICTIONARY_MEMBERS, MAX_FIELD_BYTES, MAX_INNER_LIST_ITEMS, MAX_PARAMETERS,
                  Key, sign_request)
from fiki.errors import MalformedSignatureInput, UnsupportedComponent
from fiki.messages import _parse

CORPUS = Path(__file__).resolve().parents[2] / "vectors" / "third_party" / "structured-field-tests"

# Every file's case count, read once from the corpus at 00462dd when this test was written. A
# refresh that adds, drops or empties a file fails here rather than quietly changing what is
# covered. No case in any file is skipped.
COUNTS = {
    "binary.json": 17,
    "boolean.json": 12,
    "date.json": 17,
    "dictionary.json": 26,
    "display-string.json": 22,
    "examples.json": 21,
    "item.json": 5,
    "key-generated.json": 640,
    "large-generated.json": 11,
    "list.json": 11,
    "listlist.json": 12,
    "number-generated.json": 193,
    "number.json": 37,
    "param-dict.json": 14,
    "param-list.json": 20,
    "param-listlist.json": 3,
    "string-generated.json": 256,
    "string.json": 14,
    "token-generated.json": 256,
    "token.json": 6,
}
TOTAL = 1593

# Every case fiki answers by a recorded decision rather than by the corpus, beyond the two rules
# every case is held to (RFC 9651's types and fiki's bounds): True if fiki refuses it. Every
# can_fail case is here or uses an RFC 9651 type, because fiki's decisions dictate one outcome.
FIKI_WAY = {
    "binary.json/unpadded": True,  # @2g4xxev9: missing padding is refused
    "binary.json/partially padded": True,  # @2g4xxev9: partial padding is refused
    "binary.json/extra padding": True,  # @2g4xxev9: padding past the final quantum is refused
    "binary.json/non-zero pad bits": False,  # @2g4xxev9: non-zero pad bits are accepted
    # can_fail because two field lines are joined inside a string; http_sfv reads the joined value
    # as the string "foo, bar", and that is fiki-py's outcome, which the other ports follow.
    "string.json/two lines string": False,
    # Not can_fail: the corpus parses an empty dictionary, and fiki refuses a signature header
    # that is present but empty after OWS (review B7, vectors/refusals.json
    # signature-header-of-spaces, @524c8qgv), as http_sfv does.
    "dictionary.json/empty dictionary": True,
}

STRUCTURES = {"dictionary": http_sfv.Dictionary, "list": http_sfv.List, "item": http_sfv.Item}


def load(name: str) -> list:
    # A JSON number with "." or an exponent is a decimal; parse_float keeps it one, so 1.0 and 1
    # stay apart, which a loader reading both as float cannot do.
    return json.loads((CORPUS / name).read_text(encoding="utf-8"), parse_float=Decimal)


def decimal(value: Decimal) -> tuple:
    return ("d", value.quantize(Decimal("0.001")))


class Expected:
    """The corpus's expected value in the notation got() renders a parse in, and its shape."""

    def __init__(self, case: dict):
        self.rfc9651 = False
        self.members = self.inner = self.params = 0
        value = case["expected"]
        kind = case["header_type"]
        if kind == "item":
            self.rendered = self.member(value)
        elif kind == "list":
            self.members = len(value)
            self.rendered = tuple(self.member(m) for m in value)
        else:
            self.members = len(value)
            self.rendered = tuple((k, self.member(m)) for k, m in value)

    def bare(self, value) -> tuple:
        if isinstance(value, bool):
            return ("?", value)
        if isinstance(value, int):
            return ("i", value)
        if isinstance(value, Decimal):
            return decimal(value)
        if isinstance(value, str):
            return ("s", value)
        kind = value["__type"]
        if kind == "token":
            return ("t", value["value"])
        if kind == "binary":
            return ("b", base64.b32decode(value["value"]))
        assert kind in ("date", "displaystring"), value
        self.rfc9651 = True
        return (kind, value["value"])

    def parameters(self, params) -> tuple:
        self.params = max(self.params, len(params))
        return tuple((k, self.bare(v)) for k, v in params)

    def member(self, pair) -> tuple:
        value, params = pair
        if isinstance(value, list):
            self.inner = max(self.inner, len(value))
            return ("(", tuple(self.member(item) for item in value), self.parameters(params))
        return (self.bare(value), self.parameters(params))

    def over_bounds(self, joined: str) -> bool:
        return (len(joined.encode("utf-8")) > MAX_FIELD_BYTES
                or self.members > MAX_DICTIONARY_MEMBERS
                or self.inner > MAX_INNER_LIST_ITEMS
                or self.params > MAX_PARAMETERS)


def got_bare(value) -> tuple:
    # Token before str, since a Token is a str; bool before int, since a bool is an int.
    if isinstance(value, http_sfv.Token):
        return ("t", str(value))
    if isinstance(value, bool):
        return ("?", value)
    if isinstance(value, int):
        return ("i", value)
    if isinstance(value, Decimal):
        return decimal(value)
    if isinstance(value, bytes):
        return ("b", value)
    assert type(value) is str, type(value)
    return ("s", value)


def got_member(member) -> tuple:
    params = tuple((k, got_bare(v)) for k, v in member.params.items())
    if isinstance(member, http_sfv.InnerList):
        return ("(", tuple(got_member(item) for item in member), params)
    return (got_bare(member.value), params)


def got(parsed) -> tuple:
    if isinstance(parsed, http_sfv.Dictionary):
        return tuple((k, got_member(m)) for k, m in parsed.items())
    if isinstance(parsed, http_sfv.List):
        return tuple(got_member(m) for m in parsed)
    return got_member(parsed)


def parse(case: dict, joined: str):
    """The case through its entry point: the parsed value, or None for fiki's malformed error.

    Anything but MalformedSignatureInput propagates and fails the test.
    """
    try:
        return _parse(joined, "Signature-Input", MalformedSignatureInput,
                      STRUCTURES[case["header_type"]])
    except MalformedSignatureInput:
        return None


def cases():
    for name in sorted(COUNTS):
        for case in load(name):
            yield pytest.param(name, case, id=f"{name}/{case['name']}")


@pytest.mark.parametrize("name, case", list(cases()))
def test_the_corpus_case(name, case):
    joined = ", ".join(case["raw"])
    case_id = f"{name}/{case['name']}"
    expected = None if case.get("must_fail") else Expected(case)
    rfc9651 = expected is not None and expected.rfc9651
    refuse = (case.get("must_fail", False) or rfc9651 or expected.over_bounds(joined))
    if case.get("can_fail"):
        assert case_id in FIKI_WAY or rfc9651, "a can_fail case with no outcome decided for fiki"
    if name in ("date.json", "display-string.json"):
        assert refuse, "an RFC 9651 case fiki would not refuse"
    refuse = FIKI_WAY.get(case_id, refuse)

    parsed = parse(case, joined)
    if refuse:
        assert parsed is None, f"fiki refuses {joined[:300]!r}, and it parsed as {got(parsed)}"
    else:
        assert parsed is not None, f"the corpus parses {joined[:300]!r}, and fiki refused it"
        assert got(parsed) == expected.rendered


def test_the_corpus_is_the_one_this_test_pins():
    files = sorted(p.name for p in CORPUS.glob("*.json"))
    assert files == sorted(COUNTS)
    for name, count in COUNTS.items():
        assert len(load(name)) == count, name
    assert sum(COUNTS.values()) == TOTAL
    # Every exception names a case the corpus still holds.
    held = {f"{name}/{case['name']}" for name in COUNTS for case in load(name)}
    assert set(FIKI_WAY) <= held


def test_every_corpus_case_ran(request):
    # Collection is the count: one parametrized test per case, none skipped or deselected silently.
    ran = [item for item in request.session.items if item.originalname == "test_the_corpus_case"]
    if ran:  # absent when the run was narrowed to other tests with -k
        per_file = {name: 0 for name in COUNTS}
        for item in ran:
            per_file[item.callspec.params["name"]] += 1
        assert per_file == COUNTS
        assert len(ran) == TOTAL


def test_a_list_or_item_entry_point_applies_every_bound():
    # The corpus has no list over sixteen members, so this one is named.
    members = ", ".join(["1"] * (MAX_DICTIONARY_MEMBERS + 1))
    with pytest.raises(MalformedSignatureInput, match="more than 16 members"):
        _parse(members, "Signature-Input", MalformedSignatureInput, http_sfv.List)
    assert len(_parse(members[3:], "Signature-Input", MalformedSignatureInput, http_sfv.List)) == 16
    with pytest.raises(MalformedSignatureInput, match="more than 16 parameters"):
        _parse("1" + "".join(f";p{i}" for i in range(17)), "Signature-Input",
               MalformedSignatureInput, http_sfv.Item)
    with pytest.raises(MalformedSignatureInput, match="over 8192 bytes|is 8193 bytes"):
        _parse("a" * 8193, "Signature-Input", MalformedSignatureInput, http_sfv.Item)
    with pytest.raises(MalformedSignatureInput, match="Date"):
        _parse("(1 @2)", "Signature-Input", MalformedSignatureInput, http_sfv.List)


# --- The serialisation subset, through the public signing API ---

KEY = Key.from_seed(bytes(range(32)))
URL = "https://api.example.com/x"
AT = 1700000000


def sign(**overrides):
    args = dict(key=KEY, method="GET", url=URL, headers={}, created=AT)
    args.update(overrides)
    return sign_request(**args)


def serialisation(name: str) -> list:
    return load(f"serialisation-tests/{name}")


UNREADABLE_KEYS = 372


def test_a_corpus_key_is_refused_as_a_label_and_as_a_component_parameter():
    ran = unreadable = 0
    for case in serialisation("key-generated.json"):
        assert case["must_fail"], case["name"]
        expected = case["expected"]
        key = expected[0][0] if case["header_type"] == "dictionary" else expected[0][1][0][0]
        with pytest.raises(ValueError, match="is not an RFC 8941 key"):
            sign(label=key)
        # Read as an RFC 8941 serialization: a key that does not parse is a component fiki
        # cannot read, and one that parses as some other parameter, such as "a,a" read as "a",
        # is a parameter fiki does not support. UnsupportedComponent either way, as in go, java
        # and csharp.
        with pytest.raises(UnsupportedComponent) as caught:
            sign(covered=["@method", '"@path";' + key])
        message = str(caught.value)
        if "as a component identifier" in message:
            unreadable += 1
        else:
            assert "the only component parameter it supports" in message, message
        ran += 1
    assert (ran, unreadable) == (378, UNREADABLE_KEYS)


def test_a_corpus_string_is_refused_as_a_keyid_a_nonce_and_a_tag():
    ran = 0
    for case in serialisation("string-generated.json"):
        assert case["must_fail"], case["name"]
        string = case["expected"][0]
        for field in ("keyid", "nonce", "tag"):
            with pytest.raises(ValueError, match="outside printable ASCII"):
                sign(**{field: string})
            ran += 1
    assert ran == 3 * 33


def test_a_corpus_number_too_big_to_serialize_is_refused_as_created():
    # Python can hand fiki a decimal as created, so the two too-big decimals run too, as a
    # TypeError, where a port whose created is an integer type has to skip them.
    ran = skipped = 0
    for case in serialisation("number.json"):
        if not case["name"].startswith("too big"):
            skipped += 1
            continue
        assert case["must_fail"], case["name"]
        number = case["expected"][0]
        if isinstance(number, Decimal):
            with pytest.raises(TypeError, match="created is a whole number of seconds"):
                sign(created=number)
        else:
            with pytest.raises(ValueError, match="fiki signs one from 0 to 999999999999999"):
                sign(created=number)
        ran += 1
    assert (ran, skipped) == (4, 5)

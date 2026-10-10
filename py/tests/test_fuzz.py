"""A deterministic, seeded mutation fuzz of the RFC 8941 parsing and of verify_request (tick 7xbw).

Inputs are the httpwg corpus's raw values (@7fexwu3s) and the Signature-Input and Signature values
of vectors/accepts.json and vectors/refusals.json. Each mutant is made by flipping, inserting and
deleting code points, truncating, and splicing two inputs, over an alphabet that holds printable
ASCII, the controls, non-ASCII letters, the C1 controls U+0080 to U+009F, U+2028 and U+2029, and
lone surrogates, which a Python str can hold although no peer can send one.

The parser may return a value or raise fiki's malformed error, nothing else. verify_request, given
a mutant as Signature-Input or Signature, may return a verdict or raise a FikiError, nothing else:
wire input is never a caller error (@5zrf8gjk). Anything else fails the test and prints the seed,
the iteration and the input, so a failure replays exactly. No dependency: random.Random is seeded
and its sequence is fixed across Python versions for the methods used here.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import http_sfv

from fiki import DEFAULT_MINIMUM, Verdict, verify_request
from fiki.errors import FikiError, MalformedSignatureInput
from fiki.messages import _parse

SEED = 0x7B3A_F1C1
ITERATIONS = 20_000
VECTORS = Path(__file__).resolve().parents[2] / "vectors"
CORPUS = VECTORS / "third_party" / "structured-field-tests"

ALPHABET = (
    [chr(c) for c in range(0x20, 0x7F)] * 4
    + [chr(c) for c in range(0x00, 0x20)] + ["\x7f"]
    + [chr(c) for c in range(0x80, 0xA0)]
    + [" ", " ", "é", "ÿ", "Ā", "中", "﻿", "�",
       "\U0001f600", "\ud800", "\udbff", "\udc00", "\udfff"]
    + list('"\\:;=,()*?@%-. \t')
)


def _seeds() -> tuple[list[str], list[dict]]:
    texts = []
    for path in sorted(CORPUS.glob("*.json")):
        for case in json.loads(path.read_text(encoding="utf-8")):
            texts.append(", ".join(case["raw"]))
    requests = []
    for name in ("accepts.json", "refusals.json"):
        for case in json.loads((VECTORS / name).read_text(encoding="utf-8"))["cases"]:
            headers = case["headers"]
            for field in ("Signature-Input", "Signature"):
                if isinstance(headers.get(field), str):
                    texts.append(headers[field])
            if "Signature-Input" in headers and "Signature" in headers:
                requests.append(case)
    return texts, requests


TEXTS, REQUESTS = _seeds()


def mutate(rng: random.Random, text: str) -> str:
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(6)
        at = rng.randint(0, len(text))
        if op == 0 and text:  # flip one code point
            at = min(at, len(text) - 1)
            text = text[:at] + rng.choice(ALPHABET) + text[at + 1:]
        elif op == 1:  # insert a run
            text = text[:at] + "".join(rng.choices(ALPHABET, k=rng.randint(1, 3))) + text[at:]
        elif op == 2:  # delete a run
            text = text[:at] + text[at + rng.randint(1, 4):]
        elif op == 3:  # truncate
            text = text[:at]
        elif op == 4:  # splice another input in
            other = rng.choice(TEXTS)
            cut = rng.randint(0, len(other))
            text = text[:at] + other[cut:cut + rng.randint(1, 40)] + text[at:]
        else:  # repeat a slice, which grows members, items and parameters
            piece = text[at:at + rng.randint(1, 20)]
            text = text[:at] + piece * rng.randint(2, 30) + text[at:]
    return text


def _policy(rng: random.Random, case: dict) -> dict:
    # Every decision stated, and varied, so both the minimum and the opt-out paths are fuzzed.
    return dict(
        max_age=rng.choice([None, 300]),
        now=1700000000,
        authorities=rng.choice([None, {"api.example.com"}]),
        minimum=rng.choice([DEFAULT_MINIMUM, None]),
        expected_aid=None,
        resolve=None,
        expected_keyid=None,
    )


def test_mutants_reach_only_fiki_outcomes():
    rng = random.Random(SEED)
    structures = (http_sfv.Dictionary, http_sfv.List, http_sfv.Item)
    for i in range(ITERATIONS):
        mutant = mutate(rng, rng.choice(TEXTS))
        structure = structures[i % 3]
        try:
            _parse(mutant, "Signature-Input", MalformedSignatureInput, structure)
        except MalformedSignatureInput:
            pass
        except Exception as ex:  # pragma: no cover - only a bug reaches here
            raise AssertionError(f"seed {SEED:#x} iteration {i}: parsing {mutant!r} as "
                                 f"{structure.__name__} raised {ex!r}") from ex

        case = rng.choice(REQUESTS)
        field = rng.choice(["Signature-Input", "Signature"])
        headers = dict(case["headers"], **{field: mutate(rng, case["headers"][field])})
        try:
            outcome = verify_request(
                method=case["method"], url=case["url"], headers=headers,
                body=None if case["body"] is None else case["body"].encode("utf-8"),
                **_policy(rng, case))
            assert isinstance(outcome, Verdict)
        except FikiError:
            pass
        except Exception as ex:  # pragma: no cover - only a bug reaches here
            raise AssertionError(f"seed {SEED:#x} iteration {i}: verify_request with {field} "
                                 f"{headers[field]!r} raised {ex!r}") from ex


def test_the_fuzz_inputs_are_all_there():
    # 237 corpus values (the vendored, hand-written files), and the two signature headers of every vector that carries them.
    assert len(TEXTS) > 237 + 2 * 100
    assert len(REQUESTS) > 100

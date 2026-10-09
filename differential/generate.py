"""Write differential/cases.json: mutated requests every port must answer identically.

`docs/user-guide.md` and `this.i` @5zrf8gjk promise that every port gives the same answer to the
same input. The shared vectors pin about two hundred chosen answers; this file asks the same
question of a few thousand inputs nobody chose, by mutating the vectors' own requests, and the
runners beside it record each port's answer so `compare.py` can fail on any disagreement (tick
7xbw).

Deterministic and stdlib-only: a fixed seed, no clock, no set or dict iteration whose order
depends on hashing. CI regenerates the file and fails if it differs from the committed one, as
ci-vectors.yml does for the vectors, so the committed cases are always what this script writes.

Every case states every verifier decision -- max_age (a number, or null to decline the check), now,
authorities (a list, or null to decline), minimum ("default", null for the explicit opt-out, or a
list) and expected_aid -- in the shared vectors' format-3 spelling, so no runner picks a default.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent / "vectors"
OUT = HERE / "cases.json"

SEED = 9421
COUNT = 3000

# A base request bigger than this is drawn a fifth as often: the few vectors that sit at the
# 8192-byte bounds are worth mutating, but at full weight they would make up most of the file's
# bytes for a small share of its cases.
LARGE = 4096

# The signature fields the profile parses, matched without regard to case as HTTP field names are.
SIGNATURE_FIELDS = ("signature-input", "signature", "content-digest")

# What a mutation inserts into a signature field: RFC 8941 punctuation, whitespace, control
# characters from C0 and C1, DEL, non-ASCII (one astral character, which is two UTF-16 units in the
# ports that count those), a line break, and whole tokens of every RFC 8941 item type, so that a
# mutation can build a well-formed structure of the wrong shape as well as a broken one.
ALPHABET = (
    list(';=,()"\\:*?-._/+%@<>[]{}!#$&\'^`|~')
    + [" ", "\t", "  ", "\r\n", "\n", "\r"]
    + ["\x00", "\x01", "\x08", "\x0b", "\x1f", "\x7f", "\x80", "\x85", "\x9f", "\xa0"]
    + ["\u00e9", "\u017f", "\u212a", "\u4e2d", "\U0001f600", "\ufeff", "\u2028"]
    + ["sig", "sig2", "keyid", "alg", "created", "expires", "nonce", "tag", "ed25519", "rsa-pss-sha512",
       "sha-256", "sha-512", "x", "*a", "a*b"]
    + ["0", "1", "-1", "1.5", "-0.0", "123456789012345", "1234567890123456", "0.0001", "1.", ".5", "1e3"]
    + ["@1700000000", "@-1", "@0", "@1.5", "@", "@99999999999999999"]
    + ['%"x"', '%"caf%c3%a9"', '%"%"', '%"%zz"', '%"%C3%A9"', '%""', '%x']
    + ['""', '"\\""', '"\\\\"', '"\\x"', '"a', ":AAAA:", "::", ":=:", ":AA=A:", "?1", "?0", "?2", "?"]
    + ['"@method"', '"@authority"', '"@path"', '"@query"', '"@target-uri"', '"@status"', '"content-digest"',
       '"host"', '"@query-param";name="a"', ';sf', ';key="x"', ';bs', ';req', ';tr']
    + ["=:", ";x", "();", "=()", '=("@method")', ", sig=:AAAA:", ",", ", ", ";created=1", ";alg=\"ed25519\""]
)

# What a mutation inserts into a URL, aimed at the authority, the target's form and its escapes.
URL_ALPHABET = (
    list(":/@?#[]%. \t") + ["//", "\\", "%2F", "%2f", "%41", "%zz", "%", "%00", "%25", "%7F", "%C3%A9", "\x00",
                           "\x7f", "\u00e9", "\u212a", "\n", "\r\n", "user@", ":@", "user:pw@", "[::1]", "[",
                           "]", ":443", ":0", ":65535", ":65536", ":08443", ":", ":-1", ":44x", "..", "./", "?",
                           "&", "=", "#frag", "*"]
)

# Whole URLs, and whole Host values, to substitute: the shapes the vectors' authority cases probe,
# combined differently.
URLS = [
    "https://api.example.com/things?limit=1",
    "https://API.EXAMPLE.COM/things?limit=1",
    "https://api.example.com./things?limit=1",
    "https://api.example.com:443/things?limit=1",
    "https://api.example.com:0443/things?limit=1",
    "https://api.example.com:8443/things?limit=1",
    "https://api.example.com:/things?limit=1",
    "https://api.example.com:65536/things",
    "http://api.example.com:80/things",
    "http://api.example.com:443/things",
    "https://user@api.example.com/things",
    "https://user:pw@api.example.com/things",
    "https://@api.example.com/things",
    "https://[2001:db8::1]/things",
    "https://[2001:db8::1]:8443/things",
    "https://[::ffff:1.2.3.4]/things",
    "https://[v1.x]/things",
    "https://[2001:db8::1/things",
    "https://2001:db8::1/things",
    "https://1.2.3.4/things",
    "https://001.002.003.004/things",
    "https://api.example.com/things?",
    "https://api.example.com/things#frag",
    "https://api.example.com/things?#",
    "https://api.example.com/th%69ngs?limit=%31",
    "https://api.example.com/th ings",
    "https://api.example.com",
    "https://api.example.com?x=1",
    "https://api.example.com/%2e%2e/things",
    "https://api.example.com/a/../things",
    "https:api.example.com/things",
    "https:/api.example.com/things",
    "https:///things",
    "HTTPS://api.example.com/things",
    "ftp://api.example.com/things",
    "//api.example.com/things",
    "//evil.example/p",
    "///things",
    "/things?limit=1",
    "/things?limit=1&sort=name",
    "things",
    "",
    "*",
    "api.example.com:443",
    "/",
    "/?",
    "/#",
    "https://api.example.com\\things",
    "https://api.example.com/things\u00e9",
    "https://api.exa\u212aple.com/things",
    "https://xn--caf-dma.example/things",
]

HOSTS = [
    "api.example.com", "API.EXAMPLE.COM", "api.example.com.", "api.example.com:443", "api.example.com:8443",
    "api.example.com:", "api.example.com:65536", "api.example.com:0", "api.example.com:00443", "other.example",
    "victim.example", "evil.example", "", " ", " api.example.com", "api.example.com ", "\tapi.example.com",
    "[2001:db8::1]", "[2001:db8::1]:8443", "[::1", "2001:db8::1", "user@api.example.com", "api.example.com, evil.example",
    "api.example.com/x", "api.example.com?x", "api.example.com#x", "api.exa\u212aple.com", "api.example.\u00e9",
    "1.2.3.4", "api.example.com\x00", "api.example.com\r\nX: y", "*",
]

# Alternative decisions, so a case is not always judged under its base vector's policy.
AUTHORITIES = [None, ["api.example.com"], ["api.example.com", "victim.example"], ["api.example.com:8443"],
               ["API.EXAMPLE.COM"], ["[2001:db8::1]:8443"], ["evil.example"]]
MINIMA = ["default", None, ["@method", "@authority", "@path", "@query"], ["@method", "@path", "@query"],
          ["@method", "@authority", "@path", "@query", "content-digest"]]
WINDOWS = [(None, 1700000000), (300, 1700000000), (300, 1700000400), (10, 1700000005), (300, 1699999800),
           (None, 1700000120), (None, 4102444810)]


def load(name: str) -> list[dict]:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))["cases"]


def mutate_text(rng: random.Random, value: str, alphabet: list[str]) -> str:
    """One edit: insert, delete, replace, splice in a span from elsewhere, or duplicate a span."""
    op = rng.random()
    pos = rng.randrange(len(value) + 1)
    if op < 0.35:
        return value[:pos] + rng.choice(alphabet) + value[pos:]
    if op < 0.55:
        return value[:pos] + value[pos + rng.randint(1, 6):]
    if op < 0.75:
        return value[:pos] + rng.choice(alphabet) + value[pos + 1:]
    a, b = sorted((pos, rng.randrange(len(value) + 1)))
    if op < 0.88:
        # Splice: move the span [a, b) to another position.
        span, rest = value[a:b], value[:a] + value[b:]
        at = rng.randrange(len(rest) + 1)
        return rest[:at] + span + rest[at:]
    return value[:b] + value[a:b] + value[b:]


def find(headers: dict[str, str], lowered: str) -> list[str]:
    return [name for name in headers if name.lower() == lowered]


def mutate_signature_fields(rng: random.Random, headers: dict[str, str]) -> None:
    present = [name for name in headers if name.lower() in SIGNATURE_FIELDS]
    roll = rng.random()
    if roll < 0.04 and present:
        del headers[rng.choice(present)]
        return
    if roll < 0.08 and present:
        # The same field again under another spelling of its name, which a port must join, refuse
        # or pick from in the same way as every other port.
        name = rng.choice(present)
        other = name.upper() if name != name.upper() else name.lower()
        if other not in headers:
            headers[other] = mutate_text(rng, headers[name], ALPHABET) if rng.random() < 0.5 else headers[name]
        return
    if roll < 0.11:
        name = rng.choice(["Content-Digest", "Signature-Input", "Signature"])
        if not find(headers, name.lower()):
            headers[name] = rng.choice(["sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", "sig=:AAAA:",
                                        'sig=("@method");created=1700000000', ""])
            return
    if not present:
        return
    for _ in range(rng.randint(1, 3)):
        name = rng.choice(present)
        headers[name] = mutate_text(rng, headers[name], ALPHABET)


def mutate_url(rng: random.Random, url: str) -> str:
    roll = rng.random()
    if roll < 0.3:
        return rng.choice(URLS)
    if roll < 0.45:
        # Keep the base's path and query, change what precedes it.
        rest = url.split("://", 1)[1] if "://" in url else url
        path = rest[rest.find("/"):] if "/" in rest else ""
        prefix = rng.choice(["https://api.example.com", "https://API.example.com", "https://api.example.com:443",
                             "https://u@api.example.com", "//api.example.com", "", "https://[::1]", "http://api.example.com",
                             "https://api.example.com:8443", "https://victim.example", "//evil.example"])
        return prefix + path
    for _ in range(rng.randint(1, 3)):
        url = mutate_text(rng, url, URL_ALPHABET)
    return url


def mutate_host(rng: random.Random, headers: dict[str, str]) -> None:
    existing = find(headers, "host")
    roll = rng.random()
    if roll < 0.15 and existing:
        del headers[existing[0]]
    elif roll < 0.25:
        name = rng.choice(["host", "HOST", "Host"])
        if name not in headers:
            headers[name] = rng.choice(HOSTS)
    elif roll < 0.4 and existing:
        headers[existing[0]] = mutate_text(rng, headers[existing[0]], URL_ALPHABET)
    else:
        headers[existing[0] if existing else "Host"] = rng.choice(HOSTS)


def decisions(rng: random.Random, base: dict) -> dict:
    """The base vector's own policy most of the time, another stated one otherwise. A null now in
    a vector means the real clock; here it is pinned, because a case must not depend on the day."""
    policy = {
        "max_age": base["max_age"],
        "now": 1700000000 if base["now"] is None else base["now"],
        "authorities": base["authorities"],
        "minimum": base["minimum"],
        "expected_aid": base["expected_aid"],
    }
    if rng.random() < 0.3:
        policy["max_age"], policy["now"] = rng.choice(WINDOWS)
    if rng.random() < 0.3:
        policy["authorities"] = rng.choice(AUTHORITIES)
    if rng.random() < 0.2:
        policy["minimum"] = rng.choice(MINIMA)
    if rng.random() < 0.05:
        policy["expected_aid"] = rng.choice([None, "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4",
                                             "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"])
    return policy


def generate() -> list[dict]:
    rng = random.Random(SEED)
    bases = load("accepts.json") + load("refusals.json")
    weights = [1 if len(json.dumps(b)) <= LARGE else 0.2 for b in bases]
    cases = []
    for n in range(COUNT):
        base = rng.choices(bases, weights)[0]
        headers = dict(base["headers"])
        url = base["url"]
        roll = rng.random()
        if roll < 0.6:
            mutate_signature_fields(rng, headers)
        elif roll < 0.8:
            url = mutate_url(rng, url)
        elif roll < 0.92:
            mutate_host(rng, headers)
        else:
            mutate_signature_fields(rng, headers)
            url = mutate_url(rng, url)
            mutate_host(rng, headers)
        cases.append({
            "id": f"{n:04d}-{base['id']}",
            "method": base["method"],
            "url": url,
            "headers": headers,
            "body": base["body"],
            **decisions(rng, base),
        })
    return cases


def render(cases: list[dict]) -> str:
    """One case per line, ASCII-only, so a regenerated file diffs by case and no port's JSON reader
    sees anything but escapes outside ASCII."""
    head = {
        "about": "Mutated requests every port must answer identically; see differential/README.md.",
        "generated_by": "differential/generate.py",
        "seed": SEED,
        "count": len(cases),
    }
    lines = [json.dumps(case, ensure_ascii=True, sort_keys=True) for case in cases]
    header = json.dumps(head, ensure_ascii=True, sort_keys=True)[:-1]
    return header + ', "cases": [\n' + ",\n".join(lines) + "\n]}\n"


def main() -> None:
    OUT.write_text(render(generate()), encoding="ascii", newline="\n")


if __name__ == "__main__":
    main()

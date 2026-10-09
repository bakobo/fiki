"""Release smoke test for fiki-py, run against the package INSTALLED FROM PyPI, never the source.

Four checks, the same four every port's smoke test makes (docs/releasing.md):
  1. plain, vector: accepts.json "default-covered-get" verifies under a pinned clock;
  2. plain, round trip: sign with a bare Ed25519 key and verify, preregistered by AID;
  3. KERI, vector: keri/requests.json "get-with-query" verifies through a resolver;
  4. KERI, round trip: sign under a caller-chosen transferable AID keyid and verify through a
     resolver under the profile's request minimum.
Usage: python smoke.py <vectors-dir>
"""

import base64
import json
import sys
from pathlib import Path

from fiki import REQUEST_MINIMUM, Key, sign_request, verify_request

VECTORS = Path(sys.argv[1])
SEED = bytes(range(32))  # the seed every plain vector signs with


def b64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def check(name, got, want):
    if got != want:
        sys.exit(f"FAIL {name}: got {got!r}, want {want!r}")
    print(f"ok   {name}")


plain = next(c for c in json.loads((VECTORS / "accepts.json").read_text())["cases"]
             if c["id"] == "default-covered-get")
verdict = verify_request(method=plain["method"], url=plain["url"], headers=plain["headers"],
                         body=None, max_age=None, now=plain["now"],
                         authorities=plain["authorities"])
check("plain vector", verdict.aid, plain["aid"])

key = Key.from_seed(SEED)
url, body = "https://api.example.com/things?limit=1", b'{"hello": "world"}'
headers = sign_request(key=key, method="POST", url=url, body=body)
verdict = verify_request(method="POST", url=url, headers=headers, body=body, max_age=300,
                         expected_aid=key.aid, authorities={"api.example.com"})
check("plain round trip", verdict.aid, key.aid)

keri = json.loads((VECTORS / "keri" / "requests.json").read_text())
table = {k["keyid"]: k for k in keri["keys"]}


def resolve(keyid):
    entry = table.get(keyid)
    return None if entry is None else b64url(entry["effective_key"])


case = next(c for c in keri["cases"] if c["id"] == "get-with-query")
request = case["request"]
verdict = verify_request(method=request["method"], url=request["url"], headers=request["headers"],
                         body=None, max_age=keri["policy"]["max_age"], skew=keri["policy"]["skew"],
                         now=case["now"], resolve=resolve, minimum=REQUEST_MINIMUM,
                         authorities=case.get("policy", {}).get("authorities"))
check("KERI vector", verdict.aid, case["expected"]["keyid"])

controller = table[case["expected"]["keyid"]]
signer = Key.from_seed(bytes.fromhex(controller["seed_hex"]))
url = "https://keria.example.com/identifiers?type=rot"
headers = sign_request(key=signer, method="GET", url=url, keyid=controller["keyid"],
                       minimum=REQUEST_MINIMUM)
verdict = verify_request(method="GET", url=url, headers=headers, body=None, max_age=300,
                         resolve=resolve, minimum=REQUEST_MINIMUM, authorities=None)
check("KERI round trip", verdict.aid, controller["keyid"])

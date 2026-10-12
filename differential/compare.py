"""Fail if the six ports gave different answers to any case in differential/cases.json.

`python3 differential/compare.py [out-dir] [cases.json]` reads <port>.json for each of the six ports
from out-dir (differential/out by default), each a map from case id to the outcome that port's
runner recorded, and exits non-zero if any case has more than one distinct outcome across the ports,
if any outcome is a crash, or if any port's map is missing or does not hold exactly the cases in
cases.json (differential/cases.json by default). The case ids come from cases.json, never from the
maps, so six runners that skip the same cases cannot agree their way past the check.

There is no allowlist. A disagreement is a broken promise (`this.i` @5zrf8gjk), and the place to
settle it is the port that is wrong, or the vectors if the promise needs stating, never here.

One normalization, and only one: a caller error is compared by its class, "caller", and not by its
wording. The shared vectors deliberately carry no message for a caller error, since each port words
its own (py/tests/test_vectors.py, CALLER_MESSAGES), so two ports refusing the same call in
different words agree. A port that calls the same input a caller error where another refuses or
accepts the request still disagrees, and the full wording is printed when it does.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

PORTS = ("py", "js", "go", "rust", "java", "csharp")
HERE = Path(__file__).resolve().parent


def compared(outcome: str) -> str:
    return "caller" if outcome.startswith("caller:") else outcome


def main() -> int:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "out"
    cases_path = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "cases.json"
    listed = [case["id"] for case in json.loads(cases_path.read_text(encoding="utf-8"))["cases"]]
    ids = set(listed)
    if not ids:
        print(f"{cases_path} holds no cases, so nothing would be compared.")
        return 1
    if len(ids) != len(listed):
        # A map holds one outcome per id, so two cases sharing one would be compared as one.
        twice = sorted(i for i, n in Counter(listed).items() if n > 1)
        print(f"{cases_path} gives {len(twice)} id(s) to more than one case, such as {twice[0]}")
        return 1
    maps = {}
    for port in PORTS:
        path = out_dir / f"{port}.json"
        if not path.is_file():
            print(f"{port}: no outcome map at {path}")
            return 1
        maps[port] = json.loads(path.read_text(encoding="utf-8"))
    failed = False
    for port, outcomes in maps.items():
        missing = ids - set(outcomes)
        if missing:
            failed = True
            print(f"{port}: no outcome for {len(missing)} case(s), such as {sorted(missing)[0]}")
        extra = set(outcomes) - ids
        if extra:
            failed = True
            print(f"{port}: an outcome for {len(extra)} case(s) not in {cases_path.name}, such as "
                  f"{sorted(extra)[0]}")

    disagreements = crashes = 0
    for case_id in sorted(ids):
        seen = {port: maps[port].get(case_id, "(missing)") for port in PORTS}
        crashed = any(o.startswith("crash:") for o in seen.values())
        if len({compared(o) for o in seen.values()}) > 1 or crashed:
            disagreements += 1
            crashes += crashed
            print(case_id)
            for port in PORTS:
                print(f"  {port:<7} {seen[port]}")
    print(f"{len(ids)} cases, {len(PORTS)} ports: {disagreements} case(s) with more than one outcome "
          f"or a crash ({crashes} with a crash).")
    return 1 if failed or disagreements else 0


if __name__ == "__main__":
    sys.exit(main())

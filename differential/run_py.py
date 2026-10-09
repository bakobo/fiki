"""The Python port's answers to differential/cases.json, as a map from case id to outcome.

Run from py/ so the port is the one in this repository: `uv run python ../differential/run_py.py
[cases.json] [out.json]`. The outcome spelling is shared by all six runners and described in
differential/README.md.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from fiki import verify_request
from fiki.errors import FikiError

HERE = Path(__file__).resolve().parent
# How much of a caller error's message an outcome carries; the same in every runner.
PREFIX = 40


def outcome(case: dict) -> str:
    try:
        verdict = verify_request(
            method=case["method"],
            url=case["url"],
            headers=case["headers"],
            body=None if case["body"] is None else case["body"].encode("utf-8"),
            max_age=case["max_age"],
            now=case["now"],
            authorities=case["authorities"],
            expected_aid=case["expected_aid"],
            **({} if case["minimum"] == "default" else {"minimum": case["minimum"]}),
        )
        return "ok:" + verdict.aid
    except FikiError as error:
        return type(error).__name__
    except Exception as error:  # noqa: BLE001 -- recording anything else is the point
        # A mistake in the call is a TypeError or ValueError and never a FikiError (@5zrf8gjk).
        # fiki raises those two exactly, so a subclass such as UnicodeEncodeError is a bug.
        if type(error) in (TypeError, ValueError):
            return "caller:" + str(error)[:PREFIX]
        return "crash:" + type(error).__name__


def main() -> None:
    cases_path = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "cases.json"
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "out" / "py.json"
    cases = json.loads(cases_path.read_text(encoding="utf-8"))["cases"]
    start = time.monotonic()
    out = {case["id"]: outcome(case) for case in cases}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, sort_keys=True, indent=0) + "\n", encoding="utf-8")
    print(f"python: {len(out)} cases in {time.monotonic() - start:.1f}s")


if __name__ == "__main__":
    main()

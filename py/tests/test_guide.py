"""The samples in ``docs/user-guide.md``, run.

A guide whose code does not compile is worse than no guide: a reader trusts it, pastes it, and
loses an hour to an API that moved. These are the same calls the guide shows, so a rename that
breaks a reader's copy-paste breaks the suite first.
"""

import os
import re
import stat
from pathlib import Path

from fiki import Key, sign_request, verify_request
from fiki.errors import DigestMismatch

def test_the_guides_signing_sample_runs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    # guide: signing
    key = Key.generate()
    print(key.aid)              # register this
    fd = os.open("seed.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:  # readable by you alone
        f.write(key.seed)

    url = "https://api.example.com/things?limit=1"
    body = b'{"hello": "world"}'
    headers = sign_request(key=key, method="POST", url=url, body=body)
    # end guide

    assert key.aid.startswith("B")
    assert len(key.seed) == 32
    assert {"Signature-Input", "Signature", "Content-Digest"} <= set(headers)
    # The seed is the identity, so nobody but its owner may read it (tick 3ap7).
    assert stat.S_IMODE(os.stat("seed.bin").st_mode) == 0o600
    assert Key.from_seed(open("seed.bin", "rb").read()).aid == key.aid


def test_the_guides_verifying_sample_runs():
    key = Key.generate()
    url = "https://api.example.com/things?limit=1"
    body = b'{"hello": "world"}'
    headers = sign_request(key=key, method="POST", url=url, body=body)

    verdict = verify_request(method="POST", url=url, headers=headers, body=body, max_age=300)
    assert verdict.aid == key.aid

    # Preregistration, and declining the freshness check, both as the guide spells them.
    assert verify_request(
        method="POST", url=url, headers=headers, body=body, max_age=None, expected_aid=key.aid
    ).aid == key.aid

    try:
        verify_request(method="POST", url=url, headers=headers, body=b"tampered", max_age=None)
    except DigestMismatch:
        pass
    else:
        raise AssertionError("a swapped body should be refused")


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _marked_samples() -> list[list[str]]:
    """The samples in this file, between their "# guide:" and "# end guide" markers."""
    source = _lines(Path(__file__).read_text())
    starts = [i for i, line in enumerate(source) if line.startswith("# guide:")]
    return [source[i + 1:source.index("# end guide", i)] for i in starts]


def _guide_blocks() -> list[list[str]]:
    guide = (Path(__file__).parents[2] / "docs" / "user-guide.md").read_text()
    return [_lines(block) for block in re.findall(r"```python\n(.*?)```", guide, re.S)]


def _contains(block: list[str], sample: list[str]) -> bool:
    return any(block[i:i + len(sample)] == sample for i in range(len(block) - len(sample) + 1))


def test_every_marked_sample_is_in_the_guide_line_for_line():
    # The samples above run; this proves the guide shows the code that ran, so a reader's
    # copy-paste is the tested code rather than a paraphrase of it.
    samples = _marked_samples()
    assert len(samples) == 1
    blocks = _guide_blocks()
    for sample in samples:
        assert any(_contains(block, sample) for block in blocks), sample[0]

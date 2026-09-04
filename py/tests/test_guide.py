"""The samples in ``docs/user-guide.md``, run.

A guide whose code does not compile is worse than no guide: a reader trusts it, pastes it, and
loses an hour to an API that moved. These are the same calls the guide shows, so a rename that
breaks a reader's copy-paste breaks the suite first.
"""

from fiki import Key, sign_request, verify_request
from fiki.errors import DigestMismatch


def test_the_guides_signing_sample_runs():
    key = Key.generate()
    assert key.aid.startswith("B")
    assert len(key.seed) == 32

    url = "https://api.example.com/things?limit=1"
    body = b'{"hello": "world"}'
    headers = sign_request(key=key, method="POST", url=url, body=body)
    assert {"Signature-Input", "Signature", "Content-Digest"} <= set(headers)


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

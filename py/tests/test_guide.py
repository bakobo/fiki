"""The samples in ``docs/user-guide.md``, run.

A guide whose code does not compile is worse than no guide: a reader trusts it, pastes it, and
loses an hour to an API that moved. These are the same calls the guide shows, so a rename that
breaks a reader's copy-paste breaks the suite first.
"""

import os
import re
import stat
from pathlib import Path

import pytest

from fiki import (
    REQUEST_MINIMUM,
    RESPONSE_MINIMUM,
    Key,
    Request,
    errors,
    sign_request,
    sign_response,
    verify_request,
    verify_response,
    verifying_key,
)
from fiki.errors import DigestMismatch, FikiError

# The synthetic controller and agent of vectors/keri/, so the values are real, not placeholders.
CONTROLLER_SEED = bytes.fromhex("02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021")
CONTROLLER_AID = "ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx"
AGENT_SEED = bytes.fromhex("030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122")
AGENT_AID = "EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6"


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
    with open("seed.bin", "rb") as f:
        stored = f.read()
    assert Key.from_seed(stored).aid == key.aid


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


# --- the KERI profile ---

def _keri_request():
    key = Key.from_seed(CONTROLLER_SEED)
    aid = CONTROLLER_AID
    url = "https://keria.example.com/identifiers"
    body = b'{"name": "alice"}'

    # guide: signing with a KERI identifier
    headers = sign_request(
        key=key,                   # the AID's current signing key
        keyid=aid,                 # e.g. "ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx"
        method="POST",             # exactly as it will go on the wire
        url=url,
        body=body,
        minimum=REQUEST_MINIMUM,   # refuse to sign what a profile verifier would refuse
    )
    # end guide
    return key, url, body, headers


def _key_state():
    """The verifier's own key state: each AID to the raw bytes of its current signing key."""
    return {
        aid: verifying_key(Key.from_seed(seed).aid).public_bytes_raw()
        for aid, seed in ((CONTROLLER_AID, CONTROLLER_SEED), (AGENT_AID, AGENT_SEED))
    }


def test_the_guides_keri_signing_sample_names_the_aid():
    _, _, _, headers = _keri_request()
    assert f'keyid="{CONTROLLER_AID}"' in headers["Signature-Input"]
    assert "Content-Digest" in headers


def test_the_guides_resolver_sample_runs():
    key_state = _key_state()
    _, url, body, headers = _keri_request()

    # guide: verifying with a resolver
    def resolve(keyid):
        return key_state.get(keyid)   # 32 raw bytes of the current key, or None

    verdict = verify_request(
        method="POST", url=url, headers=headers, body=body,
        max_age=300, skew=60,
        minimum=REQUEST_MINIMUM,
        resolve=resolve,
        authorities={"keria.example.com"},   # the authorities this server answers for
    )
    # end guide
    assert verdict.keyid == verdict.aid == CONTROLLER_AID

    # An AID the resolver does not know is refused, never decoded as a key.
    with pytest.raises(errors.UnknownKey) as caught:
        verify_request(method="POST", url=url, headers=headers, body=body, max_age=300,
                       minimum=REQUEST_MINIMUM, resolve=lambda keyid: None)
    assert caught.value.keyid == CONTROLLER_AID


def test_the_guides_response_samples_run():
    key_state = _key_state()
    _, url, body, request_headers = _keri_request()
    agent = Key.from_seed(AGENT_SEED)
    agent_aid = AGENT_AID
    response_body = b'{"done": true}'

    def resolve(keyid):
        return key_state.get(keyid)

    # guide: signing a response
    request = Request(method="POST", url=url, headers=request_headers, body=body)
    response_headers = sign_response(
        key=agent,
        keyid=agent_aid,
        status=201,
        request=request,           # the request it answers, which "req" components are read from
        body=response_body,
        minimum=RESPONSE_MINIMUM,
    )
    # end guide

    # guide: verifying a response
    verdict = verify_response(
        status=201, headers=response_headers, body=response_body, request=request,
        max_age=300,
        minimum=RESPONSE_MINIMUM,
        resolve=resolve,
        expected_keyid=agent_aid,  # the AID this client is talking to
    )
    # end guide

    assert verdict.keyid == AGENT_AID
    assert '"content-digest";req' in verdict.covered

    # A response from any other AID is refused, however valid its signature.
    with pytest.raises(errors.UnknownKey):
        verify_response(status=201, headers=response_headers, body=response_body,
                        request=request, max_age=300, minimum=RESPONSE_MINIMUM,
                        resolve=resolve, expected_keyid=CONTROLLER_AID)


# guide: the new error classes
def refusal(verify) -> str:
    try:
        verify()
    except errors.UnknownKey as e:
        return f"no key state for {e.keyid}"
    except errors.UnsupportedSigner as e:
        return f"no single key of {e.keyid} signs alone"
    except errors.InsufficientCoverage as e:
        return f"the signature does not cover {e.component}"
    except errors.DuplicateComponent as e:
        return f"the covered list names {e.component} twice"
    except errors.Unauthenticated:
        return "an unsigned 401; its body is not to be trusted"
    except FikiError as e:
        return type(e).__name__
    return "verified"


def group(keyid):
    raise errors.UnsupportedSigner(
        "This AID's key state has no single key that satisfies its threshold.", keyid=keyid
    )
# end guide


def test_the_guides_error_sample_names_each_new_refusal():
    key_state = _key_state()
    key, url, body, headers = _keri_request()

    def verify(headers=headers, resolve=key_state.get, minimum=REQUEST_MINIMUM):
        return lambda: verify_request(method="POST", url=url, headers=headers, body=body,
                                      max_age=300, minimum=minimum, resolve=resolve)

    assert refusal(verify()) == "verified"
    assert refusal(verify(resolve=lambda keyid: None)) == f"no key state for {CONTROLLER_AID}"
    assert refusal(verify(resolve=group)) == f"no single key of {CONTROLLER_AID} signs alone"

    # Signed without the profile's minimum, so a profile verifier finds @query missing.
    thin = sign_request(key=key, keyid=CONTROLLER_AID, method="POST", url=url, body=body,
                        covered=["@method", "@path", "content-digest"])
    assert refusal(verify(headers=thin)) == "the signature does not cover @query"

    twice = dict(headers)
    twice["Signature-Input"] = twice["Signature-Input"].replace('("@method"', '("@method" "@method"')
    assert refusal(verify(headers=twice)) == "the covered list names @method twice"

    assert refusal(lambda: verify_response(status=401, headers={}, max_age=300)) == (
        "an unsigned 401; its body is not to be trusted"
    )
    assert refusal(verify(headers={})) == "MissingSignature"

    # A mistake in the call is not a refusal of the message, so it is never a FikiError.
    with pytest.raises(ValueError):
        verify(minimum=["@method"])()
    with pytest.raises(TypeError):
        verify_request(method="POST", url=url, headers=headers, body=body, max_age=300,
                       expected_aid=CONTROLLER_AID, resolve=key_state.get)


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


def test_the_guides_key_spelling_samples_run(tmp_path, monkeypatch):
    import json

    from fiki import aid_from

    vectors = json.loads((Path(__file__).parents[2] / "vectors" / "keys" / "keys.json").read_text())
    private = next(c for c in vectors["private"]["accepts"] if c["id"] == "ssh-keygen")
    public = next(c for c in vectors["public"]["accepts"] if c["id"] == "ssh-keygen-pub")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "alice.pub").write_text(public["input"] + "\n")
    (tmp_path / "fiki_ed25519").write_text(private["input"])

# guide: registering a key in another spelling
    registered_aid = aid_from(Path("alice.pub").read_text().rstrip("\n"))
# end guide
# guide: signing with an SSH key
    key = Key.from_openssh(Path("fiki_ed25519").read_text())
    headers = sign_request(key=key, method="GET", url="https://api.example.com/things")
# end guide
    verdict = verify_request(
        method="GET", url="https://api.example.com/things", headers=headers, max_age=300,
        expected_aid=registered_aid,
    )
    assert verdict.aid == public["aid"]


def test_every_marked_sample_is_in_the_guide_line_for_line():
    # The samples above run; this proves the guide shows the code that ran, so a reader's
    # copy-paste is the tested code rather than a paraphrase of it.
    samples = _marked_samples()
    assert len(samples) == 8
    blocks = _guide_blocks()
    for sample in samples:
        assert any(_contains(block, sample) for block in blocks), sample[0]

# fiki (Python)

[![Python](https://github.com/bakobo/fiki/actions/workflows/ci-py.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-py.yml)

The Python implementation of [fiki](../README.md). Requires Python 3.11 or newer, and depends on `cryptography` and `http-sfv` and on nothing else.

## From a fresh clone to passing tests

```sh
cd py
uv sync
uv run pytest
```

The suite enforces 100% branch coverage; a gap needs an approved `deviation:` node in the repo's `this.i`.

## Signing a request

```python
from fiki import Key, sign_request

key = Key.generate()
print(key.aid)            # register this once with whoever you call
print(key.seed.hex())     # 32 bytes; persist them somewhere the cron job can read

url = "https://api.example.com/things?limit=1"
body = b'{"hello": "world"}'
headers = sign_request(key=key, method="POST", url=url, body=body)
```

By default the signature binds the method, the host, the path, the query string, and a digest of the body. Pass the body wherever you pass the URL: fiki covers a body it is given, or refuses to sign — but it cannot cover one it never sees.

## Verifying a request

```python
from fiki import verify_request

verdict = verify_request(
    method=request.method,
    url=request.url,      # a full URL, or a path plus a Host header
    headers=request.headers,
    body=request.body,
    max_age=300,          # seconds, or None to decline the check
)
verdict.aid               # who signed it
```

`max_age` has no default and must be given. Both defaults would be wrong: a number guesses at somebody else's clock skew and replay window, and skipping the check silently is the thing the argument exists to prevent. An `expires` the signer declared is enforced either way.

## Responses, resolved keyids, and a minimum covered set

These exist for the KERI profile of RFC 9421 (`this.i` @7f28p7xk, @6g9zjsv9) and are, for now, in this port only.

```python
from fiki import (REQUEST_MINIMUM, RESPONSE_MINIMUM, Request, sign_request, sign_response,
                  verify_request, verify_response)

# A keyid that is not the key itself, such as a KERI AID, needs a resolver on the verify side.
# The resolver returns the 32 raw bytes of the key, or None; fiki never decodes the keyid itself.
headers = sign_request(key=key, method="POST", url=url, body=body, keyid=aid)
verdict = verify_request(method="POST", url=url, headers=headers, body=body, max_age=300,
                         resolve=current_key_for, minimum=REQUEST_MINIMUM)

# A response binds the request it answers with RFC 9421's req parameter.
asked = Request(method="POST", url=url, headers=request_headers, body=body)
signed = sign_response(key=key, status=200, request=asked, body=reply)
verify_response(status=200, headers=signed, body=reply, request=asked, max_age=300,
                minimum=RESPONSE_MINIMUM)
```

`minimum` refuses a signature that covers less than the named components even when it is valid, and refuses a body — `Content-Length` above zero, any `Transfer-Encoding`, or one that simply arrived — whose `content-digest` is not covered. The method is signed exactly as given, with no case change, so pass it as it will go on the wire.

## Conformance

`tests/test_rfc9421_conformance.py` signs RFC 9421's own Appendix B.2.6 request with the RFC's own published Ed25519 key and asserts the RFC's own signature, byte for byte. `tests/test_vectors.py` runs the shared `vectors/` at the repository root, which every port runs. `tests/test_keri_vectors.py` runs `vectors/keri/`, the KERI profile's set, which only this port runs so far.

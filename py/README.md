# fiki (Python)

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

## Conformance

`tests/test_rfc9421_conformance.py` signs RFC 9421's own Appendix B.2.6 request with the RFC's own published Ed25519 key and asserts the RFC's own signature, byte for byte. `tests/test_vectors.py` runs the shared `vectors/` at the repository root, which the JavaScript port runs too.

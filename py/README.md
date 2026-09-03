# fiki (Python)

The Python implementation of [fiki](../README.md). Requires Python 3.11 or newer, and depends on `cryptography` and `http-sfv` and on nothing else.

## From a fresh clone to passing tests

```sh
cd py
uv sync
uv run pytest
```

The suite enforces 100% branch coverage; a gap needs an approved `deviation:` node in the repo's `this.i`.

## Status

Under construction. The API is not yet stable and is deliberately undocumented here until it is — a README describing calls that do not exist is worse than one that admits the gap.

What the suite already pins is the conformance floor: `tests/test_rfc9421_conformance.py` signs RFC 9421's own Appendix B.2.6 request with the RFC's own published Ed25519 key and asserts the RFC's own signature, byte for byte.

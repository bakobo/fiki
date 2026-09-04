# fiki

[![CI](https://github.com/bakobo/fiki/actions/workflows/ci.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci.yml)

Sign and verify HTTP requests with a bare Ed25519 key as the identifier. Standard [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html), no KERI dependencies.

The public half of an Ed25519 key is rendered as a non-transferable AID — a 44-character `B…` string in CESR's `Ed25519N` encoding — and that string is both the identifier and the verifying key. A verifier needs no key event log, no directory lookup, and no network call to recover it. A client registers its AID once with whoever it calls, and signs from then on. There is nothing to rotate and nothing to fetch.

fiki exists for the party that needs to prove who it is and nothing else: an ESB client, a cron job, a container that calls one API. That party should not have to install a KERI stack to say its own name. If you need key rotation, delegation, credentials, or anything anchored to a key event log, you want [heti](https://github.com/bakobo/heti) instead; fiki is deliberately the floor.

## What is covered, and the one thing that is not

By default a fiki signature binds the method, the host, the path, the query string, and — whenever you hand it a body — a digest of that body. That is deliberately more than [heti](https://github.com/bakobo/heti)'s KERI dialect covers and more than it structurally can: RFC 9421 stops `@path` at the question mark, so a signature that omits `@query` cannot tell `?limit=1` from `?limit=1000000`, and a signature that omits `Content-Digest` cannot tell one request body from another. Verification recomputes the digest over the body it receives rather than trusting the header, even though the header is itself signed.

A verifier states its freshness policy and cannot avoid stating it: `verify_request` takes a required `max_age`, in seconds, or `None` to decline the check — both defaults would be wrong, since a value guesses at somebody else's clock skew and replay window and `None` skips silently. An `expires` the signer declared is enforced regardless, because accepting one without checking it sells a guarantee nobody bought.

The bound worth stating plainly: **fiki cannot cover a body it was never given.** The guarantee is that if you hand fiki the body, it is covered or fiki refuses to sign — a caller who omits it gets a valid signature over a request whose body nothing protects, and no library can detect that from the inside. If you are wiring fiki into an HTTP client, pass the body at the same place you pass the URL.

## Status

Early. The Python implementation works and is tested against RFC 9421's own vectors, but the API is not yet stable and the vector set is not yet frozen.

## Layout

fiki is polyglot on purpose. Each language implementation is a top-level directory, and all of them are checked against the same conformance vectors:

```
vectors/    conformance vectors, shared and normative
  generate.py         regenerates them; run from the repo root
  aid-lens.json       a seed to its AID and its keyid
  signature-base.json bases and signatures, byte for byte
  refusals.json       requests every implementation must refuse
py/         the Python implementation
js/         the JavaScript implementation, for browsers and Node
go/         the Go implementation
rust/       the Rust implementation
java/       the Java implementation
```

A new port adds a directory here rather than a repository, so the vectors cannot fork and drift apart. See `this.i` for why that mattered enough to shape the layout.

## Versions, and which ones interoperate

Each implementation versions independently — a fix in the Go port does not force an empty release of the other four. What tells you whether two artifacts interoperate is the **vectors format** each one declares, not its version number:

```
fiki (Python)      0.5.0    vectors format 1
fiki (JavaScript)  0.5.0    vectors format 1
fiki (Go)          0.5.0    vectors format 1
fiki (Rust)        0.5.0    vectors format 1
fiki (Java)        0.5.0    vectors format 1
```

Same format, interchangeable. The format is a monotonic integer rather than a semantic version, because a conformance contract has no meaningful minor: an implementation either satisfies the vectors or it does not, and even *adding* a case is breaking for an implementation that already shipped. Every port exports the format it satisfies and asserts that the vectors it is running declare the same one, so a port reading newer vectors fails loudly rather than passing a subset.

## Conformance

Two oracles stand behind fiki. RFC 9421's own Appendix B vectors, which no Bakobo party authored, pin the signature base and the signing algorithm — including on the signing side, since B.1.4 publishes the Ed25519 private key and Ed25519 is deterministic. The `vectors/` set pins what the RFC cannot: the AID lens, the default covered set, and the refusal to sign a body that nothing digests.

## Building

Per-language instructions live with the implementation: [`py/`](py/README.md), [`js/`](js/README.md), [`go/`](go/README.md), [`rust/`](rust/README.md), and [`java/`](java/README.md). Both run the same vectors, and neither is the reference — the vectors are.

## License

Apache-2.0.

# fiki

[![Python](https://github.com/bakobo/fiki/actions/workflows/ci-py.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-py.yml)
[![JavaScript](https://github.com/bakobo/fiki/actions/workflows/ci-js.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-js.yml)
[![Go](https://github.com/bakobo/fiki/actions/workflows/ci-go.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-go.yml)
[![Rust](https://github.com/bakobo/fiki/actions/workflows/ci-rust.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-rust.yml)
[![Java](https://github.com/bakobo/fiki/actions/workflows/ci-java.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-java.yml)

Sign and verify HTTP requests with a bare Ed25519 key as the identifier. Standard [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html), no KERI dependencies. Python, JavaScript, Go, Rust, and Java.

The public half of an Ed25519 key is rendered as a non-transferable AID — a 44-character `B…` string in CESR's `Ed25519N` encoding — and that string is both the identifier and the verifying key. A verifier needs no key event log, no directory lookup, and no network call to recover it. A client registers its AID once with whoever it calls, and signs from then on. There is nothing to rotate and nothing to fetch.

fiki exists for the party that needs to prove who it is and nothing else: an ESB client, a cron job, a container that calls one API. That party should not have to install a KERI stack to say its own name. If you need key rotation, delegation, credentials, or anything anchored to a key event log, you want [heti](https://github.com/bakobo/heti) instead; fiki is deliberately the floor.

**To use fiki in your own project, read the [user guide](docs/user-guide.md).** What follows is about the repository.

## From a clone to passing tests

Every implementation is self-contained and tests itself against the shared vectors. Pick whichever language you have a toolchain for; none of them needs the others.

```sh
git clone https://github.com/bakobo/fiki
cd fiki
```

| Language | Needs | Run the tests |
|---|---|---|
| Python | [uv](https://docs.astral.sh/uv/), Python 3.11+ | `cd py && uv sync && uv run pytest` |
| JavaScript | Node 20+ | `cd js && npm test` |
| Go | Go 1.22+ | `cd go && go test ./...` |
| Rust | Rust 1.75+ | `cd rust && cargo test` |
| Java | JDK 17+, Maven | `cd java && mvn test` |

One badge per language above, each clickable through to that port's workflow — so a red badge says *which* port broke rather than that something did. A change under `vectors/` triggers all five, because the vectors are the shared contract.

The JavaScript, Go, and Java runs install nothing: fiki has no runtime dependencies in any of those three. Python fetches `cryptography` and `http-sfv`; Rust fetches `ed25519-dalek`, `sha2`, and `rand_core`, because Rust's standard library has no cryptography at all.

A green run means that implementation reproduces all 37 shared conformance vectors — including RFC 9421's own published Ed25519 signature, byte for byte.

## What is covered, and the one thing that is not

By default a fiki signature binds the method, the host, the path, the query string, and — whenever you hand it a body — a digest of that body. That is deliberately more than [heti](https://github.com/bakobo/heti)'s KERI dialect covers and more than it structurally can: RFC 9421 stops `@path` at the question mark, so a signature that omits `@query` cannot tell `?limit=1` from `?limit=1000000`, and a signature that omits `Content-Digest` cannot tell one request body from another. Verification recomputes the digest over the body it receives rather than trusting the header, even though the header is itself signed.

A verifier states its freshness policy and cannot avoid stating it: verification takes a required maximum age, in seconds, or an explicit refusal to check — both defaults would be wrong, since a value guesses at somebody else's clock skew and replay window and skipping silently is the thing the argument exists to prevent. An `expires` the signer declared is enforced regardless, because accepting one without checking it sells a guarantee nobody bought.

The bound worth stating plainly: **fiki cannot cover a body it was never given.** The guarantee is that if you hand fiki the body, it is covered or fiki refuses to sign — a caller who omits it gets a valid signature over a request whose body nothing protects, and no library can detect that from the inside. If you are wiring fiki into an HTTP client, pass the body at the same place you pass the URL.

## Status

Five implementations, all at 0.5.0, all conforming to vectors format 1. The wire behaviour is settled enough that changing it now means a vectors-format bump and five coordinated releases.

The APIs are not frozen. Nothing is published to a package registry yet, except Go, which needs no registry — `go get github.com/bakobo/fiki/go@v0.5.0` works today. Its first consumer, [heti](https://github.com/bakobo/heti), pins fiki by commit rather than by version.

## Layout

fiki is polyglot on purpose. Each language implementation is a top-level directory, and all of them are checked against the same conformance vectors:

```
docs/user-guide.md    how to use fiki, in every language
vectors/              conformance vectors, shared and normative
  generate.py             regenerates them; run from the repo root
  aid-lens.json           a seed to its AID and its keyid
  signature-base.json     bases and signatures, byte for byte
  accepts.json            requests every implementation must accept, and the verdict
  refusals.json           requests every implementation must refuse, and the error
py/                   the Python implementation
js/                   the JavaScript implementation, for browsers and Node
go/                   the Go implementation
rust/                 the Rust implementation
java/                 the Java implementation
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

Releases are tagged per port: `py/v0.5.0`, `js/v0.5.0`, `go/v0.5.0`, `rust/v0.5.0`, `java/v0.5.0`. The prefix is not cosmetic — Go's module path is `github.com/bakobo/fiki/go`, so that is the tag form its tooling requires, and the other four follow it for consistency.

## Conformance

Two oracles stand behind fiki. RFC 9421's own Appendix B vectors, which no Bakobo party authored, pin the signature base and the signing algorithm — including on the signing side, since B.1.4 publishes the Ed25519 private key and Ed25519 is deterministic. The `vectors/` set pins what the RFC cannot: the AID lens, `@query`, `Content-Digest`, the freshness rules, and the refusal to sign a body that nothing digests.

No implementation is the reference. The vectors are, and all five answer to them equally.

## Contributing a port

Add a top-level directory, run `vectors/*.json`, and export the vectors format you satisfy. If your port needs a case the vectors do not have, add it to `vectors/generate.py` and regenerate — every other port then has to satisfy it too, which is the point.

Per-language build and test notes live with each implementation: [`py/`](py/README.md), [`js/`](js/README.md), [`go/`](go/README.md), [`rust/`](rust/README.md), and [`java/`](java/README.md).

## License

Apache-2.0.

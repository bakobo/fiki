# fiki

[![Python](https://github.com/bakobo/fiki/actions/workflows/ci-py.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-py.yml)
[![JavaScript](https://github.com/bakobo/fiki/actions/workflows/ci-js.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-js.yml)
[![Go](https://github.com/bakobo/fiki/actions/workflows/ci-go.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-go.yml)
[![Rust](https://github.com/bakobo/fiki/actions/workflows/ci-rust.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-rust.yml)
[![Java](https://github.com/bakobo/fiki/actions/workflows/ci-java.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-java.yml)
[![C#](https://github.com/bakobo/fiki/actions/workflows/ci-csharp.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-csharp.yml)

Sign and verify HTTP requests with a bare Ed25519 key as the identifier. Standard [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html), no KERI dependencies. Python, JavaScript, Go, Rust, Java, and C#.

The public half of an Ed25519 key is rendered as a non-transferable AID — a 44-character `B…` string in CESR's `Ed25519N` encoding — and that string is both the identifier and the verifying key. A verifier needs no key event log, no directory lookup, and no network call to recover it. A client registers its AID once with whoever it calls, and signs from then on. There is nothing to rotate and nothing to fetch.

The AID is only one spelling of that key. A client can register it as the raw key in base64url (a JWK's `x`), a `did:key`, a `did:peer:0`, or an `ssh-ed25519` public line, and sign with an unencrypted OpenSSH private key, so a party that already has a DID, or is willing to make a dedicated SSH key, needs nothing new. The wire format does not change: whatever spelling a key was registered in, a request carries it the same way.

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
| C# | .NET 10 SDK | `cd csharp && dotnet test` |

One badge per language above, each clickable through to that port's workflow — so a red badge says *which* port broke rather than that something did. A change under `vectors/` triggers all six, because the vectors are the shared contract.

The JavaScript, Go, and Java runs install nothing: fiki has no runtime dependencies in any of those three. Python fetches `cryptography` and `http-sfv`; Rust fetches `ed25519-dalek`, `sha2`, and `rand_core`, because Rust's standard library has no cryptography at all; C# fetches `BouncyCastle.Cryptography`, because .NET's has no Ed25519 yet, along with xUnit and coverlet for the tests.

A green run means that implementation reproduces every shared conformance vector, 238 cases at vectors format 3 — including RFC 9421's own published Ed25519 signature, byte for byte.

## What is covered, and the one thing that is not

By default a fiki signature binds the method, the host, the path, the query string, and — whenever you hand it a body — a digest of that body. That is deliberately more than [heti](https://github.com/bakobo/heti)'s KERI dialect covers and more than it structurally can: RFC 9421 stops `@path` at the question mark, so a signature that omits `@query` cannot tell `?limit=1` from `?limit=1000000`, and a signature that omits `Content-Digest` cannot tell one request body from another. Verification recomputes the digest over the body it receives rather than trusting the header, even though the header is itself signed.

A verifier holds a signature to the same standard by default. From vectors format 3 it refuses one that covers less than fiki's own signer does, one with no `created`, and a body that arrived without a covered digest; a verifier that must admit a signer covering less says so explicitly. It also states which hosts it serves, or that it declines to check, so that a request signed for one service cannot be replayed to another. The coverage policy has a fail-closed default that only an explicit opt-out relaxes; the hosts have no default at all, for the same reason as the freshness policy below.

A verifier states its freshness policy and cannot avoid stating it: verification takes a required maximum age, in seconds, or an explicit refusal to check — both defaults would be wrong, since a value guesses at somebody else's clock skew and replay window and skipping silently is the thing the argument exists to prevent. An `expires` the signer declared is enforced regardless, because accepting one without checking it sells a guarantee nobody bought.

The bound worth stating plainly: **fiki cannot cover a body it was never given.** The guarantee is that if you hand fiki the body, it is covered or fiki refuses to sign — a caller who omits it gets a valid signature over a request whose body nothing protects, and no library can detect that from the inside. If you are wiring fiki into an HTTP client, pass the body at the same place you pass the URL.

## Status

Six implementations, all released at 0.8.0, conforming to vectors format 2 and to the KERI profile's keri vectors format 4. The default branch is at vectors format 3 and keri vectors format 5, unreleased: request and response verifiers fail closed by default, a server states the hosts it serves and a client the AID it expects, and every untrusted value is bounded (`this.i` @524c8qgv). That is breaking for any caller, and will ship as six coordinated releases.

The APIs are not frozen; this is 0.x. Each port is published to the registry its ecosystem expects, by a tag-triggered workflow that needs no long-lived credential ([docs/releasing.md](docs/releasing.md)), except the Java port, which is not yet on Maven Central and is built from source:

[![PyPI](https://img.shields.io/pypi/v/fiki)](https://pypi.org/project/fiki/) [![npm](https://img.shields.io/npm/v/@bakobo/fiki)](https://www.npmjs.com/package/@bakobo/fiki) [![crates.io](https://img.shields.io/crates/v/fiki)](https://crates.io/crates/fiki) [![NuGet](https://img.shields.io/nuget/v/Bakobo.Fiki)](https://www.nuget.org/packages/Bakobo.Fiki) [![Go Reference](https://pkg.go.dev/badge/github.com/bakobo/fiki/go.svg)](https://pkg.go.dev/github.com/bakobo/fiki/go)

```sh
pip install fiki==0.8.0
npm install @bakobo/fiki@0.8.0
go get github.com/bakobo/fiki/go@v0.8.0
cargo add fiki@0.8.0
dotnet add package Bakobo.Fiki --version 0.8.0
```

Versions 0.0.1 on PyPI, npm, crates.io and NuGet are empty placeholders that reserved the names; do not depend on them. Its first consumer, [heti](https://github.com/bakobo/heti), pins fiki by commit rather than by version.

## Layout

fiki is polyglot on purpose. Each language implementation is a top-level directory, and all of them are checked against the same conformance vectors:

```
docs/user-guide.md    how to use fiki, in every language
docs/keri-profile.md  the KERI profile of RFC 9421, which vectors/keri/ pins
vectors/              conformance vectors, shared and normative
  generate.py             regenerates them; run from the repo root
  aid-lens.json           a seed to its AID and its keyid
  signature-base.json     bases and signatures, byte for byte
  accepts.json            requests every implementation must accept, and the verdict
  refusals.json           requests every implementation must refuse, and the error
  keri/                   the KERI profile of RFC 9421's own set, format keri_vectors_format 4;
                          all six ports run it
  keys/                   the spellings of an Ed25519 key fiki reads, format key_vectors_format 1,
                          with OpenSSH fixtures written by ssh-keygen; Python runs it so far
py/                   the Python implementation
js/                   the JavaScript implementation, for browsers and Node
go/                   the Go implementation
rust/                 the Rust implementation
java/                 the Java implementation
csharp/               the C# implementation, for .NET and .NET Framework
```

A new port adds a directory here rather than a repository, so the vectors cannot fork and drift apart. See `this.i` for why that mattered enough to shape the layout.

## Versions, and which ones interoperate

Each implementation versions independently — a fix in the Go port does not force an empty release of the other five. What tells you whether two artifacts interoperate is the **vectors format** each one declares, not its version number:

```
fiki (Python)      0.8.0    vectors format 2    keri vectors format 4
fiki (JavaScript)  0.8.0    vectors format 2    keri vectors format 4
fiki (Go)          0.8.0    vectors format 2    keri vectors format 4
fiki (Rust)        0.8.0    vectors format 2    keri vectors format 4
fiki (Java)        0.8.0    vectors format 2    keri vectors format 4
fiki (C#)          0.8.0    vectors format 2    keri vectors format 4
```

The Python port, from its next release, also satisfies key vectors format 1 (`vectors/keys/`); the other ports do not read the alternate key spellings yet.

Same format, interchangeable; the columns are compared separately, so two artifacts can agree on one and not the other. The format is a monotonic integer rather than a semantic version, because a conformance contract has no meaningful minor: an implementation either satisfies the vectors or it does not, and even *adding* a case is breaking for an implementation that already shipped. Every port exports the format it satisfies and asserts that the vectors it is running declare the same one, so a port reading newer vectors fails loudly rather than passing a subset.

Releases are tagged per port: `py/v0.8.0`, `js/v0.8.0`, `go/v0.8.0`, `rust/v0.8.0`, `java/v0.8.0`, `csharp/v0.8.0`. The prefix is not cosmetic — Go's module path is `github.com/bakobo/fiki/go`, so that is the tag form its tooling requires, and the other five follow it for consistency.

## Conformance

Two oracles stand behind fiki. RFC 9421's own Appendix B vectors, which no Bakobo party authored, pin the signature base and the signing algorithm — including on the signing side, since B.1.4 publishes the Ed25519 private key and Ed25519 is deterministic. The `vectors/` set pins what the RFC cannot: the AID lens, `@query`, `Content-Digest`, the freshness rules, and the refusal to sign a body that nothing digests.

No implementation is the reference. The vectors are, and all six answer to them equally.

`vectors/keri/` is a separate contract with its own format number (`this.i` @8vwrexxc). It pins the [KERI profile of RFC 9421](docs/keri-profile.md) that keripy, KERIA and signify-ts implement — responses bound to their request with `req`, keyids that are KERI AIDs resolved by the verifier, a minimum covered set, and refusals named by the profile's neutral codes — and it also carries, as static data, the legacy-dialect messages KERIA's and signify-ts's tests pin today. The Python port generates it, and all six ports run it. How to sign and verify under the profile, in each language, is in the [user guide](docs/user-guide.md#signing-with-a-keri-identifier).

## Contributing a port

Add a top-level directory, run `vectors/*.json`, and export the vectors format you satisfy. If your port needs a case the vectors do not have, add it to `vectors/generate.py` and regenerate — every other port then has to satisfy it too, which is the point.

Per-language build and test notes live with each implementation: [`py/`](py/README.md), [`js/`](js/README.md), [`go/`](go/README.md), [`rust/`](rust/README.md), [`java/`](java/README.md), and [`csharp/`](csharp/README.md).

## License

Apache-2.0.

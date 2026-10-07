# fiki (Java)

[![Java](https://github.com/bakobo/fiki/actions/workflows/ci-java.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-java.yml)

The Java implementation of [fiki](../README.md). Requires JDK 17 or newer, and has **no runtime dependencies** — Ed25519 has been in the JDK since 15, SHA-2 since forever, and the RFC 8941 subset is hand-rolled in `Sfv.java`. JUnit and Jackson are test-scope only; a consumer of this artifact inherits neither.

```sh
cd java
mvn test
```

## Signing a request

```java
Key key = Key.generate();                 // or Key.fromSeed(seed)
System.out.println(key.aid());            // register this once with whoever you call

byte[] body = "{\"hello\": \"world\"}".getBytes(UTF_8);
Map<String, String> headers = Fiki.signRequest(key, "POST",
    "https://api.example.com/things?limit=1", Map.of(),
    Fiki.SignOptions.none().withBody(body));
```

By default the signature binds the method, the host, the path, the query string, and a digest of the body. Pass the body wherever you pass the URL: fiki covers a body it is given, or refuses to sign — but it cannot cover one it never sees.

## Verifying a request

```java
Fiki.Verdict verdict = Fiki.verifyRequest(method, url, headers,
    Fiki.VerifyOptions.maxAge(300).withBody(body));
```

There is no `VerifyOptions` constructor that leaves the freshness policy unstated: it is either `maxAge(seconds)` or `decliningFreshness()`. Both defaults would be wrong — a number guesses at somebody else's clock skew and replay window, and skipping the check silently is the thing the choice exists to prevent. An `expires` the signer declared is enforced either way.

## The KERI profile

The port implements the [KERI profile of RFC 9421](../docs/keri-profile.md) and runs every file under `vectors/keri/` in place (`KeriVectorsTest`), declaring `Fiki.KERI_VECTORS_FORMAT = 2` beside `Fiki.VECTORS_FORMAT`. That adds `signResponse` and `verifyResponse` with `@status` and `Fiki.req("@path")`, a caller-chosen keyid (`SignOptions.withKeyid`), an authoritative `Fiki.Resolver` (`VerifyOptions.withResolver`), the minimum covered sets `Fiki.REQUEST_MINIMUM` and `Fiki.RESPONSE_MINIMUM`, `withExpectedKeyid` and `withAuthorities`, and refusals in the profile's section 9 order.

```java
Map<String, String> headers = Fiki.signRequest(key, "POST", url, Map.of(),
    Fiki.SignOptions.none().withBody(body).withKeyid(aid).withMinimum(Fiki.REQUEST_MINIMUM));

Fiki.Verdict verdict = Fiki.verifyRequest("POST", url, headers,
    Fiki.VerifyOptions.maxAge(300).withBody(body)
        .withResolver(keyid -> keyState.get(keyid))      // 32 raw bytes, or null if unknown
        .withMinimum(Fiki.REQUEST_MINIMUM));
```

## Differences from the Python port

Behaviour is fiki-py's and the surface is Java's (`this.i` @24tvlxgd). Where the two pull apart:

- A refusal is one `FikiException` whose `kind()` is a `FikiException.Kind` named exactly as the Python exception class, rather than a class per refusal, and `detail()` carries the offending value. Its constructor is public so that a `Resolver` can throw `UnsupportedSigner` or `MalformedKey` itself.
- A mistake in the call rather than the message is an `IllegalArgumentException`, where Python raises `TypeError` for some and `ValueError` for others: an expected AID together with a resolver, a minimum smaller than the profile's, a response binding the request's digest verified without the request body, served authorities passed to `verifyResponse`, an empty method, a port that is not a number from 0 to 65535, and a header map that names one field under two spellings.
- The resolver is a synchronous functional interface, the request a response answers is a `Fiki.Request` record, and options are `SignOptions` and `VerifyOptions` records built with `with…` methods. `VerifyOptions` holds a `Fiki.Freshness` value, and its canonical constructor refuses a null one, so no constructor leaves the freshness decision unstated: it is `maxAge(seconds)`, `decliningFreshness()`, or `Freshness.DECLINED` passed explicitly. A maximum age or skew that is not positive is refused.

Some refusals are stricter than fiki-py's today, each in the fail-closed direction and each recorded in `this.i`:

- A key that is a small-order Ed25519 point, or not the canonical encoding of a point on the curve, is `MalformedKey` before any signature check, whether it came from a keyid, an expected AID or a resolver (@2kc2c4h5, @3kdzr0zn).
- A covered field value is checked for control characters on the value as received, and only then are spaces and tabs trimmed, so a value ending in CR LF is refused rather than read as the value without it (@3cceqvg3).
- Under a minimum covered set, a keyid is required even when the verifier names the key (@6hsuwdh8).
- A signer refuses a caller-supplied `Content-Digest` that does not hold for the body, and each header map is read once into one canonical form (@0ms4j0ef).
- A signer refuses a keyid, nonce or tag that is not an RFC 8941 string, a label that is not an RFC 8941 key, and a `created` or `expires` beyond fifteen digits. A received URL whose authority cannot be read is `SignatureMismatch`, where Python raises a bare `ValueError`, and a 401 with an empty `Signature` header is `Unauthenticated` (@2r05k9g0).

And a few edges are read as RFC 3986 and RFC 8941 write them (@8yucn7nv): an IPv6 literal in `@authority` keeps its brackets, where Python drops them; the parser reads tokens and decimals and refuses an integer of more than fifteen digits; and parsing is linear in the number of parameters and members.

## How a seed becomes a key pair

Worth knowing, because it is the one place this port does something unusual and the reason is not obvious.

The JCA offers **no way to derive an Ed25519 public key from a private one**. `EdECPrivateKey` exposes the seed bytes and the parameter spec and nothing else, and no `KeyFactory` spec yields the public half. That matters because the AID *is* the public key, so `fromSeed` has to produce it somehow. The alternatives were a cryptography dependency — which would have put this port in the same column as Rust — or hand-written curve arithmetic, which is not a thing to write.

What works instead is seeding the provider's key-pair generator: SunEC's Ed25519 generator draws exactly 32 bytes and uses them as the seed, so a `SecureRandom` that hands back the caller's seed produces the caller's key pair.

That is provider behaviour rather than a specified contract, so `fromSeed` does not trust it. It reads the seed back out of the generated private key and throws if the generator used something else, and the shared `aid-lens` vector is the standing tripwire. A JDK that changes this fails loudly at the call rather than quietly producing the wrong AID.

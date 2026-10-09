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
    Fiki.VerifyOptions.maxAge(300).withBody(body).withAuthorities(Set.of("api.example.com")));
```

There is no `VerifyOptions` constructor that leaves the freshness policy unstated: it is either `maxAge(seconds)` or `decliningFreshness()`. Both defaults would be wrong — a number guesses at somebody else's clock skew and replay window, and skipping the check silently is the thing the choice exists to prevent. An `expires` the signer declared is enforced either way.

The authorities a request verifier serves are a required decision too (@524c8qgv): `withAuthorities(collection)` names the hosts, compared exactly with the derived `@authority`, and `withoutAuthorityCheck()` declines the check. `verifyRequest` refuses options that state neither with an `IllegalArgumentException`, as it refuses an empty collection or one holding anything but strings. A minimum left unstated is `Fiki.DEFAULT_MINIMUM`, fiki's own signing default, so a verifier at its defaults accepts what a fiki signer produces and nothing that covers less; `withoutMinimum()` opts out.

A response verifier states the keyid it expects in the same way (@524c8qgv): `withExpectedKeyid(aid)` names the AID the client is talking to, and `withoutKeyidCheck()` accepts any signer, named in the verdict's `keyid`. `verifyResponse` refuses options that state neither, and an empty AID is never the decline. Its minimum left unstated is `Fiki.RESPONSE_MINIMUM`; `withoutMinimum()` opts out.

## The KERI profile

The port implements the [KERI profile of RFC 9421](../docs/keri-profile.md) and runs every file under `vectors/keri/` in place (`KeriVectorsTest`), declaring `Fiki.KERI_VECTORS_FORMAT = 5` beside `Fiki.VECTORS_FORMAT = 3`. That adds `signResponse` and `verifyResponse` with `@status` and `Fiki.req("@path")`, a caller-chosen keyid (`SignOptions.withKeyid`), an authoritative `Fiki.Resolver` (`VerifyOptions.withResolver`), the minimum covered sets `Fiki.REQUEST_MINIMUM` and `Fiki.RESPONSE_MINIMUM`, `withExpectedKeyid` and `withAuthorities`, and refusals in the profile's section 9 order.

```java
Map<String, String> headers = Fiki.signRequest(key, "POST", url, Map.of(),
    Fiki.SignOptions.none().withBody(body).withKeyid(aid).withMinimum(Fiki.REQUEST_MINIMUM));

Fiki.Verdict verdict = Fiki.verifyRequest("POST", url, headers,
    Fiki.VerifyOptions.maxAge(300).withBody(body)
        .withResolver(keyid -> keyState.get(keyid))      // 32 raw bytes, or null if unknown
        .withMinimum(Fiki.REQUEST_MINIMUM)
        .withAuthorities(Set.of("keria.example.com")));
```

## Differences from the Python port

Behaviour is fiki-py's and the surface is Java's (`this.i` @24tvlxgd). Where the two pull apart:

- A refusal is one `FikiException` whose `kind()` is a `FikiException.Kind` named exactly as the Python exception class, rather than a class per refusal, and `detail()` carries the offending value. Its constructor is public so that a `Resolver` can throw `UnsupportedSigner` or `MalformedKey` itself.
- A mistake in the call rather than the message is an `IllegalArgumentException`, where Python raises `TypeError` for some and `ValueError` for others: an expected AID together with a resolver, a minimum smaller than the profile's, a response binding the request's digest verified without the request body, served authorities passed to `verifyResponse`, a `verifyResponse` whose options state neither `withExpectedKeyid(aid)` nor `withoutKeyidCheck()`, an empty expected keyid, a userinfo-bearing or over-long URL being signed, a method that is not an HTTP token, a port that is not a number from 0 to 65535 in a URL being signed, a header map that names one field under two spellings or holds a null, a caller-supplied `Content-Digest` that does not parse, names no algorithm fiki computes or contradicts the body, a keyid, nonce or tag outside printable ASCII, a label that is not an RFC 8941 key, a component name that is not a field name, and a `created` or `expires` outside 0 to 999999999999999.
- The resolver is a synchronous functional interface, the request a response answers is a `Fiki.Request` record, and options are `SignOptions` and `VerifyOptions` records built with `with…` methods. `VerifyOptions` holds a `Fiki.Freshness` value, and its canonical constructor refuses a null one, so no constructor leaves the freshness decision unstated: it is `maxAge(seconds)`, `decliningFreshness()`, or `Freshness.DECLINED` passed explicitly. A maximum age or skew that is not positive is refused.

Since 0.8.0 every port gives the same answer to the same input (@5zrf8gjk), so what used to be listed here as Java being stricter is now the rule everywhere:

- A key that is a small-order Ed25519 point, or not the canonical encoding of a point on the curve, is `MalformedKey` before any signature check, whether it came from a keyid, an expected AID or a resolver.
- A keyid's own well-formedness is checked first, then an expected keyid (a mismatch is `UnknownKey`, and the resolver is never asked), and only then the resolver.
- A covered field value is checked for control characters on the value as received, and only then are spaces and tabs trimmed. `Content-Length` is likewise trimmed of SP and HTAB only, so a vertical tab or a no-break space makes it something other than a decimal, which counts as a body.
- A received URL whose port is not a number from 0 to 65535 is `SignatureMismatch` when a covered component needs the URL, and is not read otherwise. `:000080` is port 80, and an empty port is no port. TAB, CR and LF anywhere in a URL are removed before it is read, as Python's `urlsplit` removes them.
- The RFC 8941 parser is strict: no integer of more than fifteen digits, no decimal without a fractional digit, and a byte sequence only as canonically padded base64. Parsing is linear.
- Signature-Input, Signature and Content-Digest are bounded before they are parsed: `Fiki.MAX_FIELD_BYTES` (8192) bytes each, `Fiki.MAX_DICTIONARY_MEMBERS` (16) members, `Fiki.MAX_INNER_LIST_ITEMS` (64) items in an inner list and `Fiki.MAX_PARAMETERS` (16) parameters on an item. Over any of them is that header's malformed kind.
- A target URL, a Host that supplies `@authority`, and every other covered field value are bounded at the same `Fiki.MAX_FIELD_BYTES`, in UTF-8 bytes as received, inclusive. Over it is a base that cannot be built: `SignatureMismatch` on verify, and on sign an `IllegalArgumentException` for a URL and `SignatureMismatch` for a field value. An error message quotes at most 64 characters of any untrusted value, escaped, and says how long it was.
- `Verdict.keyid()` is the keyid exactly as it appeared on the wire, or null when there was none; `Verdict.aid()` is the identity that vouched for the key.

An IPv6 or IPvFuture literal in `@authority` keeps its brackets (@8yucn7nv).

## How a seed becomes a key pair

Worth knowing, because it is the one place this port does something unusual and the reason is not obvious.

The JCA offers **no way to derive an Ed25519 public key from a private one**. `EdECPrivateKey` exposes the seed bytes and the parameter spec and nothing else, and no `KeyFactory` spec yields the public half. That matters because the AID *is* the public key, so `fromSeed` has to produce it somehow. The alternatives were a cryptography dependency — which would have put this port in the same column as Rust — or hand-written curve arithmetic, which is not a thing to write.

What works instead is seeding the provider's key-pair generator: SunEC's Ed25519 generator draws exactly 32 bytes and uses them as the seed, so a `SecureRandom` that hands back the caller's seed produces the caller's key pair.

That is provider behaviour rather than a specified contract, so `fromSeed` does not trust it. It reads the seed back out of the generated private key and throws if the generator used something else, and the shared `aid-lens` vector is the standing tripwire. A JDK that changes this fails loudly at the call rather than quietly producing the wrong AID.

# fiki (Java)

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

## How a seed becomes a key pair

Worth knowing, because it is the one place this port does something unusual and the reason is not obvious.

The JCA offers **no way to derive an Ed25519 public key from a private one**. `EdECPrivateKey` exposes the seed bytes and the parameter spec and nothing else, and no `KeyFactory` spec yields the public half. That matters because the AID *is* the public key, so `fromSeed` has to produce it somehow. The alternatives were a cryptography dependency — which would have put this port in the same column as Rust — or hand-written curve arithmetic, which is not a thing to write.

What works instead is seeding the provider's key-pair generator: SunEC's Ed25519 generator draws exactly 32 bytes and uses them as the seed, so a `SecureRandom` that hands back the caller's seed produces the caller's key pair.

That is provider behaviour rather than a specified contract, so `fromSeed` does not trust it. It reads the seed back out of the generated private key and throws if the generator used something else, and the shared `aid-lens` vector is the standing tripwire. A JDK that changes this fails loudly at the call rather than quietly producing the wrong AID.

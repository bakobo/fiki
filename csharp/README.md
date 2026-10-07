# fiki (C#)

[![C#](https://github.com/bakobo/fiki/actions/workflows/ci-csharp.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-csharp.yml)

The .NET implementation of [fiki](https://github.com/bakobo/fiki): sign and verify HTTP requests and responses per RFC 9421, with a bare Ed25519 key as the identifier. The library targets **netstandard2.0** and **net10.0**, so it loads on .NET Framework as well as on current .NET (CI runs it on .NET Framework 4.8.1), and it has **one runtime dependency**, BouncyCastle.Cryptography; see below for why. Building and testing it needs the .NET 10 SDK.

```sh
cd csharp
dotnet test
```

That runs the suite on net10.0. To hold the library to 100% line and branch coverage, as CI does, add `-p:CollectCoverage=true`; the build fails below it. On Windows the suite also runs on .NET Framework 4.8.1 (net481), which is what proves the netstandard2.0 asset rather than asserting it. Elsewhere, `dotnet build -p:FikiNet481=true` compiles that asset without running it.

The suite runs RFC 9421's own Appendix B example, every case in the shared `vectors/` (vectors format 1), and every case in the KERI profile's `vectors/keri/` (KERI vectors format 2). This port follows fiki-py rather than the Java, Go, JavaScript and Rust ports, so it is the second, after Python, to pass both sets.

## Signing a request

```csharp
using System.Text;
using Bakobo.Fiki;

var key = Key.Generate();                  // or Key.FromSeed(seed)
Console.WriteLine(key.Aid);                // register this once with whoever you call

var body = Encoding.UTF8.GetBytes("{\"hello\": \"world\"}");
var headers = HttpSignatures.SignRequest(key, "POST",
    "https://api.example.com/things?limit=1", body: body);
```

`headers` holds `Signature-Input`, `Signature`, and the `Content-Digest` fiki computed. By default the signature binds the method, the host, the path, the query string, and a digest of the body. Pass the body wherever you pass the URL: fiki covers a body it is given, or refuses to sign, but it cannot cover one it never sees. The method is signed exactly as given, so pass it as it will go on the wire.

## Verifying a request

```csharp
var verdict = HttpSignatures.VerifyRequest(method, url, headers,
    VerifyOptions.MaxAge(300).WithBody(body));
```

There is no `VerifyOptions` constructor that leaves the freshness policy unstated: it is `VerifyOptions.MaxAge(seconds)` or `VerifyOptions.DecliningFreshness()`. Both defaults would be wrong: a number guesses at somebody else's clock skew and replay window, and skipping the check silently is the thing the choice exists to prevent. An `expires` the signer declared is enforced either way.

A refusal is a `FikiException` whose `Kind` names the obstacle. The `FikiErrorKind` names are fiki-py's class names, which the vectors pin, so a refusal reads the same in every port. A caller mistake rather than a message defect, such as a minimum covered set below the KERI profile's, is an `ArgumentException`.

Responses are signed and verified the same way, with `HttpSignatures.SignResponse` and `HttpSignatures.VerifyResponse`; `VerifyOptions.WithRequest` names the request a response answers, and `HttpSignatures.Req("@path")` names one of its components. `WithResolver` supplies keys for keyids such as KERI AIDs, and `WithMinimum(HttpSignatures.RequestMinimum)` applies the KERI profile's minimum covered set.

## The BouncyCastle dependency, and why

.NET has no Ed25519 in its standard library. The API is approved (dotnet/runtime#63174) but has not shipped, so this port takes a dependency where the Go, Java and JavaScript ports take none, and sits beside Rust in that respect (`this.i` @5l4p36rl, @2tt6fmc0).

It takes **BouncyCastle.Cryptography**, pinned exactly, rather than NSec.Cryptography, because BouncyCastle is pure managed code. NSec wraps libsodium and ships a native binary per runtime identifier, and a native library that fails to load inside somebody's enterprise container is a failure fiki's callers would hit at the worst moment. BouncyCastle also derives the public key from a 32-byte seed directly, which spares this port the provider workaround the Java port needs. Hand-written curve arithmetic was never a candidate. SHA-256 and SHA-512 come from the base class library, and the RFC 8941 structured-field subset is hand-rolled, as in every port.

The cost is a large library of which fiki uses one algorithm, and one more maintainer outside Bakobo in the supply chain. CI checks that the packed library declares BouncyCastle.Cryptography and nothing else, for each target framework.

A key that is a small-order point, in any of its encodings, is refused as `MalformedKey` when it is decoded from a keyid, read from an AID, or returned by a resolver, before the algorithm or the signature is looked at. Against such a key a signature anyone can write verifies, and OpenSSL, which fiki-py uses, accepts it. The check is BouncyCastle's `Ed25519.ValidatePublicKeyPartial`, which also refuses bytes that are no canonical point on the curve; fiki-py reports those as a `SignatureMismatch` instead. `Key.ToAid` will not render such a key.

## How this port reproduces fiki-py

fiki-py's behaviour is partly its dependencies' behaviour, so this port reproduces two of them rather than reaching for .NET's equivalents, which differ:

- **urllib.parse.urlsplit**, which py derives `@authority`, `@path` and `@query` from. `System.Uri` normalizes paths and percent-encoding, and would build a different signature base from the same URL.
- **http_sfv**, py's RFC 8941 parser, including where it departs from the RFC, because which header parses decides between one refusal and another.

Each is checked against an oracle generated from the Python original (`test/Bakobo.Fiki.Tests/oracle/`), and the oracle scripts say how to regenerate it.

One divergence is deliberate: an IPv6 literal keeps its brackets in `@authority`, so `https://[::1]:8443/x` gives `[::1]:8443` as RFC 9421 section 2.2.3 and RFC 3986 section 3.2.2 spell it, where fiki-py gives `::1:8443` (tick 2h2g). The JavaScript port keeps them too; no vector pins either form yet.

Another is a refusal fiki-py does not make: `SignRequest` and `SignResponse` throw `ArgumentException` for a label that is not an RFC 8941 dictionary key, such as `"bad label"` or `"Sig"`, where fiki-py writes headers no verifier can parse. Nothing valid on the wire changes.

A third: headers holding two field names equal case-insensitively, such as `X-Role` and `x-role`, are refused with `ArgumentException` on every signing and verifying entry point, the paired `Request` included, as the Rust port refuses them (conductor ruling D-Q9ZT). fiki-py keeps the later value; refusing means no message verifies over one value while carrying another an application might read.

And under a minimum covered set, a signature with no keyid is `MissingKey` even when `WithExpectedAid` names the key, since the KERI profile makes keyid required; fiki-py on main accepts it, and bakobo/fiki#9 brings it into line.

A field value is checked as received and only SP and HTAB are trimmed from it (`this.i` @56qu7gyw): a covered value with a CR, LF, NUL or other byte outside visible ASCII around it is a `SignatureMismatch`, where fiki-py's `str.strip` removes CR, LF and Unicode whitespace first and verifies what is left.

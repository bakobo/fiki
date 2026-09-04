# fiki user guide

How to use fiki in Python, JavaScript, Go, Rust, and Java. If you want to work *on* fiki rather than with it, the [README](../README.md) covers the repository and each port's own README covers its build.

## The idea, in one page

A fiki identity is an Ed25519 key pair, and the identifier *is* the public key — rendered as a non-transferable AID, a 44-character string starting with `B`:

```
BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4
```

Because the identifier is the key, a verifier recovers the key from the identifier by decoding it. There is no directory to consult, no key event log to replay, and no network call at any point. That is the whole trick, and everything else follows from it.

The lifecycle has two steps and no third:

1. **Register once.** Generate a key, keep the 32-byte seed somewhere only you can read, and give your AID to whoever you will be calling. An email, a config file, a row in their database — fiki does not care how.
2. **Sign every request.** The signature travels in standard RFC 9421 `Signature` and `Signature-Input` headers, and carries your public key inline, so the server can check it against the AID it has on file.

There is nothing to rotate, because a non-transferable AID cannot rotate — a new key is a new identity, and re-registering is how you replace one. If that is the wrong model for you, and you need rotation or delegation or credentials, you want [heti](https://github.com/bakobo/heti); fiki is deliberately the floor.

## What a signature actually protects

By default a fiki signature covers the **method**, the **host**, the **path**, the **query string**, and — whenever you hand it a body — a **digest of that body**.

The query string matters more than it looks. RFC 9421 stops `@path` at the question mark, so a signature that omits `@query` cannot tell `GET /things?limit=1` from `GET /things?limit=1000000`. The body matters for the obvious reason. fiki covers both by default because a signature that leaves them out is a weaker guarantee than most people assume they are getting.

Three consequences worth knowing before you wire it in.

**fiki cannot cover a body it was never given.** If you hand it the body, it is covered or fiki refuses to sign. If you forget to pass it, you get a valid signature over a request whose body nothing protects, and no library can detect that from the inside. Pass the body wherever you pass the URL.

**Verification recomputes the digest.** It does not trust the `Content-Digest` header, even though that header is itself signed — a covered digest still only attests to a body nobody hashed until somebody hashes it. This means the verifier needs the whole body in memory, so fiki cannot verify a streamed request.

**You must state a freshness policy.** Verification takes a maximum age in seconds, or an explicit refusal to check. There is no default, because both candidates are wrong: a number guesses at your clock skew and replay window, and skipping silently is exactly what the argument exists to prevent. Separately, if a signer declared an `expires`, fiki enforces it whatever you chose — accepting one without checking it would sell a guarantee nobody bought.

## Signing a request

Generate a key once, print the AID, and register it. Then sign.

### Python

```python
from fiki import Key, sign_request

key = Key.generate()
print(key.aid)              # register this
open("seed.bin", "wb").write(key.seed)

url = "https://api.example.com/things?limit=1"
body = b'{"hello": "world"}'
headers = sign_request(key=key, method="POST", url=url, body=body)
# headers -> {"Signature-Input": ..., "Signature": ..., "Content-Digest": ...}
```

### JavaScript

```js
import { Key, signRequest } from '@bakobo/fiki';

const key = await Key.generate();      // non-extractable; see "Keys in a browser"
console.log(key.aid);

const url = 'https://api.example.com/things?limit=1';
const body = new TextEncoder().encode(JSON.stringify({ hello: 'world' }));
const headers = await signRequest({ key, method: 'POST', url, body });
await fetch(url, { method: 'POST', body, headers });
```

### Go

```go
key, err := fiki.FromSeed(seed)     // or fiki.Generate()
fmt.Println(key.AID())

headers, err := fiki.SignRequest(key, "POST",
    "https://api.example.com/things?limit=1", nil,
    fiki.SignOptions{Body: []byte(`{"hello": "world"}`)})
```

### Rust

```rust
let key = Key::from_seed(&seed)?;   // or Key::generate()
println!("{}", key.aid());

let headers = sign_request(&key, "POST",
    "https://api.example.com/things?limit=1", &BTreeMap::new(),
    &SignOptions { body: Some(body.to_vec()), ..Default::default() })?;
```

### Java

```java
Key key = Key.generate();
System.out.println(key.aid());

Map<String, String> headers = Fiki.signRequest(key, "POST",
    "https://api.example.com/things?limit=1", Map.of(),
    Fiki.SignOptions.none().withBody(body));
```

## Verifying a request

The server side. `url` can be a full URL or just the request target — if it is relative, fiki takes the authority from the `Host` header, which is what RFC 9421 says the authority *is* in HTTP/1.1. That is the shape a server-side handler actually has, so no reconstruction is needed.

### Python

```python
from fiki import verify_request
from fiki.errors import FikiError

try:
    verdict = verify_request(
        method=request.method, url=request.url, headers=request.headers,
        body=request.body, max_age=300,
    )
except FikiError as e:
    return 401, str(e)

if verdict.aid != registered_aid_for_this_client:
    return 403, "not the client we expected"
```

### JavaScript

```js
import { verifyRequest, FikiError } from '@bakobo/fiki';

const verdict = await verifyRequest({
  method, url, headers, body, maxAge: 300,
});
```

### Go

```go
maxAge := int64(300)
verdict, err := fiki.VerifyRequest(r.Method, r.URL.String(), headers,
    fiki.VerifyOptions{Body: body, MaxAge: &maxAge})
```

### Rust

```rust
let verdict = verify_request(method, url, &headers, &VerifyOptions {
    max_age: Some(300),
    body: Some(body.to_vec()),
    ..Default::default()
})?;
```

### Java

```java
Fiki.Verdict verdict = Fiki.verifyRequest(method, url, headers,
    Fiki.VerifyOptions.maxAge(300).withBody(body));
```

A verdict carries the **AID that signed** and the **components the signature actually covered**. Comparing the AID against the one you registered is the authorization step, and it is yours: fiki tells you who signed, never whether they are allowed.

### Preregistration

If you already know whose request this should be, say so, and fiki verifies against that key rather than the one the request carries. Python: `expected_aid=`. JavaScript: `expectedAid`. Go: `ExpectedAID`. Rust: `expected_aid`. Java: `.withExpectedAid(...)`.

That closes the gap where a request carries a perfectly valid signature from the wrong party. Without it, you get a verdict naming a stranger and you have to compare it yourself, which works but puts the check in your code rather than fiki's.

## Declining the freshness check

Sometimes you have replay protection elsewhere — a nonce store, a gateway, an idempotency key — and an age limit would be redundant. Say so explicitly:

| Language | Check the age | Decline |
|---|---|---|
| Python | `max_age=300` | `max_age=None` |
| JavaScript | `maxAge: 300` | `maxAge: null` |
| Go | `MaxAge: &seconds` | `MaxAge: nil` |
| Rust | `max_age: Some(300)` | `max_age: None` |
| Java | `VerifyOptions.maxAge(300)` | `VerifyOptions.decliningFreshness()` |

Omitting it entirely is an error, not a default. That is the point: the decision is visible at the call site either way.

Clock skew is tolerated at 5 seconds by default and is adjustable, because two hosts disagreeing by a second is ordinary and a verifier that treats it as an attack is unusable.

## Handling errors

Every refusal has a named type, and the names are identical across all five languages because the conformance vectors pin them. Catch the base type to mean "this request was not usable", or discriminate when you care which obstacle you hit.

The ones worth handling separately:

- `SignatureMismatch` — the signature does not verify. Something was tampered with, or the client signed with a different key.
- `SignatureTooOld` / `SignatureExpired` — the signature is fine and too late. Often a clock problem rather than an attack; worth logging with both timestamps.
- `DigestMismatch` — the body does not match its digest. The body was replaced in transit.
- `UncoveredBody` — raised at *signing* time, when you named a covered set that omits `content-digest` while handing over a body. Add it, or do not pass the body.
- `MissingSignature` / `MissingSignatureInput` — the request is not signed at all, which usually means an unauthenticated caller rather than a broken one.

Access differs by language: Python and JavaScript use exception classes, Go exposes `Error.Kind`, Rust exposes `Error.kind`, and Java exposes `FikiException.kind()`.

## Choosing your own covered set

The default is right for almost everyone. If you override it, fiki stops helping and starts obeying: naming a covered set that omits `content-digest` while passing a body becomes a refusal rather than a silent addition, because adding a component you did not ask for would mean signing more than you agreed to.

Derived components fiki builds: `@method`, `@authority`, `@path`, `@query`. Anything else is refused rather than skipped — a component silently dropped from the base is one you believe is covered and is not. `@target-uri` is deliberately absent: it binds the scheme, which a client behind a TLS-terminating proxy cannot reproduce.

## Keys in a browser

JavaScript only, and worth reading before you ship a single-page app.

`Key.generate()` returns a **non-extractable** key: JavaScript cannot read its private half, so an XSS bug cannot exfiltrate it. Store the object itself in IndexedDB, which persists a `CryptoKey` without ever exposing the bytes. The cost is that the identity belongs to that browser profile — a new device registers a new AID, and `key.seed` throws.

When an identity has to outlive the profile, ask for it:

```js
const key = await Key.generate({ extractable: true });
await save(key.seed);        // 32 bytes, and now your problem to protect
```

The safe shape is the default and the portable one is explicit, because a browser and a server have genuinely different threat models.

## Interoperating with heti

[heti](https://github.com/bakobo/heti) is fiki's first consumer and speaks fiki's dialect through `VanillaRfc9421Dialect`, which delegates to fiki and maps its errors onto heti's own code taxonomy. A fiki-signed request verifies through heti unchanged.

heti also speaks a second, older dialect — the KERI flavour that keria and signify-ts use. That one covers less (no query string, no host, no body) and is not interchangeable with fiki's; which dialect a service accepts is a deployment decision rather than a fallback chain.

## These samples are tested

Every snippet above is exercised by a test in its own port — `py/tests/test_guide.py`, `js/test/guide.test.js`, `go/guide_test.go`, `rust/examples/guide.rs`, `java/.../GuideTest.java`. A guide whose code does not run is worse than no guide, so a rename that would break your copy-paste breaks the suite first.

## Which version works with which

Each port versions independently. What tells you two artifacts interoperate is the **vectors format** they declare, not their version numbers — every port exports it as a constant. All five are at vectors format 1 today. See the [README](../README.md#versions-and-which-ones-interoperate) for why the two numbers are separate.

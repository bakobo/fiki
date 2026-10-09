# fiki user guide

How to use fiki in Python, JavaScript, Go, Rust, Java, and C#. If you want to work *on* fiki rather than with it, the [README](../README.md) covers the repository and each port's own README covers its build.

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
import os
from fiki import Key, sign_request

key = Key.generate()
print(key.aid)              # register this
fd = os.open("seed.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as f:  # readable by you alone
    f.write(key.seed)

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

### C#

```csharp
using System.Text;
using Bakobo.Fiki;

var key = Key.Generate();                  // or Key.FromSeed(seed)
Console.WriteLine(key.Aid);                // register this
byte[] seed = key.Seed;                    // 32 bytes: store them where only you can read them

var url = "https://api.example.com/things?limit=1";
var body = Encoding.UTF8.GetBytes("{\"hello\": \"world\"}");
var headers = HttpSignatures.SignRequest(key, "POST", url, body: body);
// headers -> Signature-Input, Signature, Content-Digest
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

### C#

```csharp
Verdict verdict;
try
{
    verdict = HttpSignatures.VerifyRequest(method, url, headers,
        VerifyOptions.MaxAge(300).WithBody(body)
            .WithAuthorities(new[] { "api.example.com" }));   // the hosts this server answers for
}
catch (FikiException e)
{
    throw new UnauthorizedAccessException(e.Message, e);   // a 401
}

if (verdict.Aid != registeredAidForThisClient)
{
    throw new UnauthorizedAccessException("not the client we expected");   // a 403
}
```

A verdict carries the **AID that signed** and the **components the signature actually covered**. Comparing the AID against the one you registered is the authorization step, and it is yours: fiki tells you who signed, never whether they are allowed.

### Preregistration

If you already know whose request this should be, say so, and fiki verifies against that key rather than the one the request carries. Python: `expected_aid=`. JavaScript: `expectedAid`. Go: `ExpectedAID`. Rust: `expected_aid`. Java: `.withExpectedAid(...)`. C#: `.WithExpectedAid(...)`.

That closes the gap where a request carries a perfectly valid signature from the wrong party. Without it, you get a verdict naming a stranger and you have to compare it yourself, which works but puts the check in your code rather than fiki's.

### Registering a key in another spelling

The AID is one spelling of an Ed25519 public key, and a client may hand you another. fiki reads five, and converts each to the AID you compare against:

| Spelling | Example shape |
|---|---|
| The AID | `BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4` |
| The raw key, unpadded base64url, which is also a JWK's `x` member | `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg` |
| A did:key, base58btc | `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK` |
| A did:peer with numalgo 0 | `did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH` |
| An OpenSSH public key line, comment optional | `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@laptop` |

Convert when you load your registrations, not on each request. A bad registration then fails when your service starts, and `expected_aid` and the verdict's AID stay in the one spelling that never needs guessing.

```python
from pathlib import Path
from fiki import aid_from

registered_aid = aid_from(Path("alice.pub").read_text().rstrip("\n"))
```

Then pass `registered_aid` as `expected_aid`, or compare it with the verdict's AID, exactly as above.

Every spelling has exactly one accepted form. fiki strips nothing, so trim a line ending yourself, and it refuses as `MalformedKey` anything it would otherwise have to guess at: surrounding whitespace, base64 with stray padding or non-zero spare bits, base58 with an extra leading `1`, a did:key whose key is not Ed25519 or whose value is not base58btc, a DID URL with a fragment, an SSH line with an options prefix, and a transferable `D…` AID, whose current key the identifier alone cannot tell you. An SSH comment must be printable ASCII and may not begin or end with a space; a comment like `josé@höst` is refused, so edit it out of the line. A key of small order is refused in every spelling, as it is in a keyid. Only the JWK's `x` member is read rather than the whole JWK, so that no port needs a JSON parser for it.

The did:key spec's grammar also admits a base64url value beginning with `u`, but its resolution algorithm requires `z`, and peer DIDs allow only `z`, so fiki reads `z` alone. A refusal never quotes what it was given, because the thing handed over by mistake is sometimes a private key: the `.key` file instead of the `.pub`.

Python has this today. The other ports will follow against the same vectors, `vectors/keys/`, which carry their own format number, `key_vectors_format`, so that adding them does not move the shared contract.

## Signing with an SSH key

If you already have an Ed25519 SSH key, you can sign with it. fiki reads an unencrypted OpenSSH private key exactly as `ssh-keygen` writes it, and the server registers the matching `.pub` line through `aid_from`.

```python
from pathlib import Path
from fiki import Key, sign_request

key = Key.from_openssh(Path("fiki_ed25519").read_text())
headers = sign_request(key=key, method="GET", url="https://api.example.com/things")
```

A passphrase-protected key is refused, because decrypting one would cost fiki dependencies it does not otherwise need. Generate a dedicated key for this rather than removing the passphrase from one you use elsewhere: `ssh-keygen -t ed25519 -N '' -f fiki_ed25519`, and do not load it into `ssh-agent`.

Do not register a key you also log in with. A fiki signature and an SSH login signature are made over data that cannot be mistaken for each other, so neither can be replayed as the other. But anything that can make SSH signatures with the key can also sign fiki requests: an `ssh-agent` signs whatever bytes it is asked to, and with agent forwarding (`ssh -A`) so can anyone with root on a host you forward to. A dedicated key that is never in an agent has neither exposure, and its file sitting where a service can read it costs you nothing else.

fiki is stricter than OpenSSH about the file in most respects: it refuses a key whose stored public half disagrees with its seed, trailing text after the armor, spaces or tabs inside the base64, extra blocks of padding, and a comment that is not printable ASCII (generate with `-C` set to something ASCII). It is more lenient in one respect: it accepts a key whose final newline is missing, which OpenSSH refuses, because a secret store or an environment variable routinely strips it. Errors about a private key never include any part of it.

## Declining the freshness check

Sometimes you have replay protection elsewhere — a nonce store, a gateway, an idempotency key — and an age limit would be redundant. Say so explicitly:

| Language | Check the age | Decline |
|---|---|---|
| Python | `max_age=300` | `max_age=None` |
| JavaScript | `maxAge: 300` | `maxAge: null` |
| Go | `MaxAge: &seconds` | `MaxAge: nil` |
| Rust | `max_age: Some(300)` | `max_age: None` |
| Java | `VerifyOptions.maxAge(300)` | `VerifyOptions.decliningFreshness()` |
| C# | `VerifyOptions.MaxAge(300)` | `VerifyOptions.DecliningFreshness()` |

Omitting it entirely is an error, not a default. That is the point: the decision is visible at the call site either way.

Clock skew is tolerated at 5 seconds by default and is adjustable, because two hosts disagreeing by a second is ordinary and a verifier that treats it as an attack is unusable.

## Signing with a KERI identifier

Everything above uses fiki's own model, where the identifier is the key. fiki also implements the [KERI profile of RFC 9421](keri-profile.md), which is what keripy, KERIA and signify-ts speak, and there the identifier is a KERI AID whose current key lives in a key event log. A transferable AID, the `E…` kind, does not contain its current key, so a verifier has to look it up.

To sign under an AID, name it as the `keyid` and sign with that AID's current key. The request is then no longer self-verifying: only a verifier that can resolve the AID can check it. Pass the profile's minimum covered set too. It is `@method`, `@path` and `@query`, plus `content-digest` whenever there is a body, and with it fiki refuses to sign anything a profile verifier would refuse rather than letting the verifier find out. The method is signed exactly as given, so pass it as it will go on the wire.

### Python

```python
from fiki import REQUEST_MINIMUM, sign_request

headers = sign_request(
    key=key,                   # the AID's current signing key
    keyid=aid,                 # e.g. "ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx"
    method="POST",             # exactly as it will go on the wire
    url=url,
    body=body,
    minimum=REQUEST_MINIMUM,   # refuse to sign what a profile verifier would refuse
)
```

### JavaScript

```js
import { Key, REQUEST_MINIMUM, signRequest } from '@bakobo/fiki';

const headers = await signRequest({
  key,                       // the AID's current signing key
  keyid: aid,                // e.g. 'EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6'
  method: 'POST',            // exactly as it will go on the wire; fiki never changes its case
  url,
  body,
  minimum: REQUEST_MINIMUM,  // refuse to sign what a profile verifier would refuse
});
```

### Go

```go
headers, err := fiki.SignRequest(key, "POST", url, nil, fiki.SignOptions{
	Keyid:   aid,                 // name the AID; the verifier resolves it
	Body:    body,                // covered by a Content-Digest, returned among the headers
	Minimum: fiki.RequestMinimum, // refuse to sign what a profile verifier would refuse
})
```

### Rust

```rust
// The keyid is the signer's KERI AID rather than its key; only a verifier that can resolve the
// AID to its current key can check the signature.
let headers = sign_request(
    key,
    "POST",
    "https://keria.example.com/identifiers",
    &BTreeMap::new(),
    &SignOptions {
        body: Some(br#"{"name": "alice"}"#.to_vec()),
        keyid: Some("ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx".into()),
        // Refuse to sign anything a KERI-profile verifier would refuse.
        minimum: Some(REQUEST_MINIMUM.map(String::from).to_vec()),
        ..Default::default()
    },
)?;
```

### Java

```java
Key key = Key.fromSeed(HexFormat.of().parseHex(
    "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"));
String aid = "ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx";   // whose current key is `key`

String url = "https://keria.example.com/identifiers";
byte[] body = "{\"name\": \"alice\"}".getBytes(UTF_8);
Map<String, String> headers = Fiki.signRequest(key, "POST", url, Map.of(),
    Fiki.SignOptions.none().withBody(body).withKeyid(aid).withMinimum(Fiki.REQUEST_MINIMUM));
```

### C#

```csharp
var headers = HttpSignatures.SignRequest(key, "POST", url, body: body,
    keyId: aid,                                  // the AID; the verifier resolves it
    minimum: HttpSignatures.RequestMinimum);     // refuse what a profile verifier would refuse
```

A covered list that falls short of the minimum is refused as `InsufficientCoverage` at signing time. Covering more is allowed, and the default covered set, which adds `@authority`, already does; the profile asks a signer that signs for a third party to keep `@authority` covered.

## Verifying with a resolver

The verifier supplies a resolver: a function from a keyid to the 32 raw bytes of that AID's current signing key, taken from the key state it holds, or nothing when it holds none. fiki does not read key event logs, so key state is the caller's to keep.

The resolver is authoritative. fiki never falls back to decoding the keyid, because a basic transferable `D…` prefix embeds its *inception* key, which may have been rotated away, and reading it would undo pre-rotation. A resolver that knows no key for the keyid makes the message `UnknownKey`. A keyid that is shaped like an AID and is not its canonical spelling is `MalformedKey` before the resolver sees it. A resolver may also refuse in fiki's own terms, most usefully as `UnsupportedSigner` for a key state that no single key can sign for, such as a 2-of-3 group, and fiki carries that refusal out unchanged. A resolver and an expected AID each decide the key alone, so passing both is a mistake in the call.

Pass the minimum here as well. A verifier that enforces it refuses a signature over too little even when the signature is valid, refuses a body that arrived without a covered `content-digest`, and requires `created`. Without a minimum, fiki checks what was signed and applies no coverage policy of its own. `authorities` lists the `@authority` values this server answers for, so that a request signed for one service cannot be replayed to another.

Supplying `authorities` makes `@authority` required, from 0.7.0 in every port. The profile's request minimum leaves `@authority` out, so a signature over the minimum commits to no host at all, and comparing a host it never covered would protect nothing: a GET signed for `attacker.example` would verify at `victim.example`. A verifier given `authorities` therefore refuses a request whose signature does not cover `@authority` as `InsufficientCoverage`, before it resolves the key, and refuses a covered `@authority` outside the set as `SignatureMismatch`, as before. A verifier given no `authorities` checks no host, unchanged.

### Python

```python
from fiki import REQUEST_MINIMUM, verify_request

def resolve(keyid):
    return key_state.get(keyid)   # 32 raw bytes of the current key, or None

verdict = verify_request(
    method="POST", url=url, headers=headers, body=body,
    max_age=300, skew=60,
    minimum=REQUEST_MINIMUM,
    resolve=resolve,
    authorities={"keria.example.com"},   # the authorities this server answers for
)
```

### JavaScript

```js
import { REQUEST_MINIMUM, verifyRequest } from '@bakobo/fiki';

const verdict = await verifyRequest({
  method, url, headers, body,
  maxAge: 300,
  minimum: REQUEST_MINIMUM,
  resolve: async (keyid) => keyState.get(keyid) ?? null,  // 32 raw bytes, or null
});
verdict.keyid;  // the AID the resolver vouched for; verdict.aid is the same
```

### Go

```go
resolve := func(keyid string) ([]byte, error) {
	key, ok := keyState[keyid] // the current key of the KEL you hold for keyid
	if !ok {
		return nil, nil // no KEL: fiki refuses the message as UnknownKey
	}
	return key, nil
}
maxAge, skew := int64(300), int64(60)
verdict, err := fiki.VerifyRequest("POST", url, headers, fiki.VerifyOptions{
	Body:        body,
	Resolve:     resolve,
	Minimum:     fiki.RequestMinimum,
	MaxAge:      &maxAge,
	Skew:        &skew,
	Authorities: []string{"keria.example.com"}, // the authorities this server answers for
})
// verdict.Keyid is the AID the resolver vouched for; verdict.AID is the same.
```

A Go resolver refuses by returning an error, which passes through unchanged: `&fiki.Error{Kind: fiki.KindUnsupportedSigner, Keyid: keyid, Message: "..."}`. Three fields distinguish nil from empty: a nil `Minimum` applies no minimum, a nil `Authorities` checks no authority while an empty one serves nothing, and a nil `Body` is no body while an empty one is a body of no bytes.

### Rust

```rust
// The resolver maps a keyid to the 32 raw bytes of its CURRENT key, from the verifier's own
// key state. It is authoritative: fiki never decodes the keyid as a key instead. None means
// "no key known", which fiki reports as Kind::UnknownKey.
let resolve: Resolver = Arc::new(move |keyid: &str| Ok(key_state.get(keyid).copied()));

let verdict = verify_request(
    "POST",
    "https://keria.example.com/identifiers",
    headers,
    &VerifyOptions {
        max_age: Some(300),
        body: Some(body.to_vec()),
        resolve: Some(resolve),
        minimum: Some(REQUEST_MINIMUM.map(String::from).to_vec()),
        ..Default::default()
    },
)?;
assert_eq!(verdict.aid, "ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx");
```

A `Resolver` is an `Arc<dyn Fn(&str) -> fiki::Result<Option<[u8; 32]>> + Send + Sync>`. It refuses with `Err(Error::detailed(Kind::UnsupportedSigner, "...", keyid))`; `Error::new` and `Error::detailed` are public for that purpose.

### Java

```java
Map<String, byte[]> keyState = ...;   // each AID to the raw 32 bytes of its current signing key
Fiki.Resolver resolver = keyid -> keyState.get(keyid);   // 32 raw bytes, or null if unknown
Fiki.Verdict verdict = Fiki.verifyRequest("POST", url, headers,
    Fiki.VerifyOptions.maxAge(300).withBody(body).withResolver(resolver)
        .withMinimum(Fiki.REQUEST_MINIMUM));
String signer = verdict.keyid();   // the AID the resolver vouched for
```

A Java resolver refuses by throwing `new FikiException(FikiException.Kind.UnsupportedSigner, message, keyid)`.

### C#

```csharp
Func<string, byte[]?> resolve = keyid =>
    keyState.TryGetValue(keyid, out var current) ? current : null;   // null: UnknownKey

var verdict = HttpSignatures.VerifyRequest("POST", url, headers,
    VerifyOptions.MaxAge(300).WithSkew(60).WithBody(body)
        .WithResolver(resolve)
        .WithMinimum(HttpSignatures.RequestMinimum)
        .WithAuthorities(new[] { "keria.example.com" }));   // the authorities this server answers for
// verdict.Aid is the AID the resolver vouched for
```

A C# resolver refuses by throwing:

```csharp
throw new FikiException(FikiErrorKind.UnsupportedSigner,
    "This AID's key state has no single key that satisfies its threshold.", keyid);
```

The verdict's AID is the keyid the resolver vouched for, so the authorization step is the same as before: compare it with the AID you expect.

## Signing and verifying a response

The profile signs responses too, and binds each one to the request it answers. By default a signed response covers `@status`, a digest of its own body, and the request's `@method`, `@path` and `@query` marked `req` (RFC 9421 §2.4), plus the request's `content-digest` when the request had content. So an intermediary can neither change the status or the body nor attach the response to a different question. Pass the request with the body it carried: a response that binds `"content-digest";req` is checked against that body, and fiki cannot check a body it was not given, so verifying one against a request with no body is a mistake in the call. A request that had content and no `Content-Digest` to bind is refused as `UncoveredBody` at signing time. To name the covered list yourself, spell a request component with the port's `req` helper, which turns `@path` into `"@path";req`.

A client names the AID it expects to be talking to, and a response signed by any other is refused as `UnknownKey`, however valid its signature. An unsigned 401 is `Unauthenticated`, checked before anything else, because a server that refuses a request before it knows which agent it is cannot sign the refusal; its body is not to be trusted. `authorities` applies to requests only.

### Python

```python
from fiki import RESPONSE_MINIMUM, Request, sign_response

request = Request(method="POST", url=url, headers=request_headers, body=body)
response_headers = sign_response(
    key=agent,
    keyid=agent_aid,
    status=201,
    request=request,           # the request it answers, which "req" components are read from
    body=response_body,
    minimum=RESPONSE_MINIMUM,
)
```

```python
from fiki import RESPONSE_MINIMUM, verify_response

verdict = verify_response(
    status=201, headers=response_headers, body=response_body, request=request,
    max_age=300,
    minimum=RESPONSE_MINIMUM,
    resolve=resolve,
    expected_keyid=agent_aid,  # the AID this client is talking to
)
```

### JavaScript

```js
import { RESPONSE_MINIMUM, signResponse } from '@bakobo/fiki';

const request = { method, url, headers: requestHeaders, body: requestBody };
const responseHeaders = await signResponse({
  key,
  keyid: aid,
  status: 200,
  request,                    // the request it answers, which "req" components are read from
  body: responseBody,
  minimum: RESPONSE_MINIMUM,
});
```

```js
import { RESPONSE_MINIMUM, verifyResponse } from '@bakobo/fiki';

const verdict = await verifyResponse({
  status: 200, headers: responseHeaders, body: responseBody, request,
  maxAge: 300,
  minimum: RESPONSE_MINIMUM,
  resolve,
  expectedKeyid: aid,         // the AID this client is talking to
});
```

### Go

```go
request := &fiki.Request{Method: "POST", URL: url, Headers: headers, Body: body}
responseBody := []byte(`{"done": true}`)
responseHeaders, err := fiki.SignResponse(agentKey, 200, request, nil, fiki.SignOptions{
	Keyid:   agentAID,
	Body:    responseBody,
	Minimum: fiki.ResponseMinimum,
})
```

```go
verdict, err = fiki.VerifyResponse(200, request, responseHeaders, fiki.VerifyOptions{
	Body:          responseBody,
	Resolve:       resolve,
	Minimum:       fiki.ResponseMinimum,
	ExpectedKeyid: agentAID, // the AID you meant to talk to (profile R1)
	MaxAge:        &maxAge,
	Skew:          &skew,
})
```

### Rust

```rust
// `request` is the request being answered, with the body that arrived. By default the
// response covers @status, its own body's digest, and the request's method, path, query and
// digest, each marked `req` -- which binds the answer to the question.
let response_headers = sign_response(
    agent,
    200,
    Some(&request),
    &BTreeMap::new(),
    &SignOptions {
        body: Some(br#"{"done": true}"#.to_vec()),
        keyid: Some("EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6".into()),
        minimum: Some(RESPONSE_MINIMUM.map(String::from).to_vec()),
        ..Default::default()
    },
)?;
```

```rust
// A client names the AID it is talking to, so a response signed by anyone else is refused.
let verdict = verify_response(
    200,
    response_headers,
    Some(request),
    &VerifyOptions {
        max_age: Some(300),
        body: Some(br#"{"done": true}"#.to_vec()),
        resolve: Some(resolve),
        expected_keyid: Some("EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6".into()),
        minimum: Some(RESPONSE_MINIMUM.map(String::from).to_vec()),
        ..Default::default()
    },
)?;
assert_eq!(
    verdict.keyid.as_deref(),
    Some("EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6")
);
```

### Java

```java
Key agent = Key.fromSeed(HexFormat.of().parseHex(
    "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122"));
String agentAid = "EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6";
byte[] responseBody = "{\"done\": true}".getBytes(UTF_8);

Fiki.Request asked = new Fiki.Request("POST", url, requestHeaders, body);
Map<String, String> responseHeaders = Fiki.signResponse(agent, 201, asked, Map.of(),
    Fiki.SignOptions.none().withBody(responseBody).withKeyid(agentAid)
        .withMinimum(Fiki.RESPONSE_MINIMUM));
```

```java
Fiki.Verdict answer = Fiki.verifyResponse(201, responseHeaders, asked,
    Fiki.VerifyOptions.maxAge(300).withBody(responseBody).withResolver(resolver)
        .withExpectedKeyid(agentAid).withMinimum(Fiki.RESPONSE_MINIMUM));
```

### C#

```csharp
var request = new Request("POST", url, requestHeaders, body);   // the request it answers
var responseHeaders = HttpSignatures.SignResponse(agent, 201, request,
    body: responseBody, keyId: agentAid,
    minimum: HttpSignatures.ResponseMinimum);
```

```csharp
var answer = HttpSignatures.VerifyResponse(201, responseHeaders,
    VerifyOptions.MaxAge(300).WithBody(responseBody).WithRequest(request)
        .WithResolver(resolve)
        .WithExpectedKeyId(agentAid)                 // the AID this client is talking to
        .WithMinimum(HttpSignatures.ResponseMinimum));
```

In every port, `request_headers` (or its equivalent) is the request as it arrived, signature headers and `Content-Digest` included.

The binding is to what was asked, not to one particular request: two identical GETs produce identical `req` values, so a recorded response to the first can answer the second while it is still fresh. The profile accepts that, and explains why, in [§3](keri-profile.md#3-covered-components).

### Legacy KERI signatures

fiki implements only the profile's canonical mode. The legacy mode KERIA and signify-ts deploy today, with its `Signify-Resource` header and non-RFC signature base, is not verified by fiki (`this.i` @8vwrexxc); verify it with keripy or KERIA, or, for an imbu-style server, with [heti](https://github.com/bakobo/heti)'s KERI dialect.

## What fiki refuses before it reads a signature

Since 0.8.0 every port applies the same limits and the same strict parsing, so a request one port accepts is one every port accepts.

- Size comes first. `Signature-Input`, `Signature` and `Content-Digest` may each be at most 8192 bytes, a dictionary at most 16 members, a covered list at most 64 components, and any item at most 16 parameters. Anything larger is refused as the malformed error for that header, before it is parsed. Each port exports the four limits (`MAX_FIELD_BYTES`, `MAX_DICTIONARY_MEMBERS`, `MAX_INNER_LIST_ITEMS`, `MAX_PARAMETERS`, in its own spelling).
- RFC 8941 is read strictly. An integer longer than 15 digits, a decimal with no fractional digit, and a byte sequence that is not canonically padded base64 (missing or partial padding, `=` in the middle, or any character outside the alphabet) are refused.
- A port in a URL is any run of digits, read as a number, so `:000080` is port 80. A port that is not a number, or is above 65535, means the signature base cannot be built, and a verifier refuses with `SignatureMismatch`.
- A small-order or off-curve Ed25519 key is refused as `MalformedKey` before any signature check, whichever way it arrived.
- When signing, fiki refuses rather than emits what would not verify. That covers a method that is not an HTTP token, a keyid, nonce or tag outside printable ASCII, a label that is not an RFC 8941 key, a component name that is not a lowercase field name, a timestamp beyond 15 digits, and a supplied `Content-Digest` that does not match the body. These are caller errors in each language's idiom, not fiki errors.
- `max_age` and `skew` must be positive. Declining the freshness check is still done the way "Declining the freshness check" shows.
- `Verdict.keyid` is the keyid exactly as it appeared on the wire. `Verdict.aid` is the identity that vouched for the key.

## Handling errors

Every refusal of a message has a name, and the names are the same in all six languages: `SignatureMismatch` is `SignatureMismatch` everywhere. Catch the base type to mean "this message was not usable", or discriminate when you care which obstacle you hit.

The ones worth handling separately:

- `SignatureMismatch` — the signature does not verify. Something was tampered with, or the client signed with a different key.
- `SignatureTooOld` / `SignatureExpired` — the signature is fine and too late. Often a clock problem rather than an attack; worth logging with both timestamps.
- `DigestMismatch` — the body does not match its digest. The body was replaced in transit.
- `UncoveredBody` — raised at *signing* time, when you named a covered set that omits `content-digest` while handing over a body. Add it, or do not pass the body.
- `MissingSignature` / `MissingSignatureInput` — the request is not signed at all, which usually means an unauthenticated caller rather than a broken one.

The KERI profile added five more, and one older name matters more under it:

- `UnknownKey` — the resolver has no key for the keyid, or a response came from an AID other than the one you expected.
- `UnsupportedSigner` — the AID's key state has no single key that can sign alone. fiki never decides this itself; a resolver raises it and fiki carries it out.
- `InsufficientCoverage` — the signature may well be valid, and it covers less than the minimum you asked for.
- `DuplicateComponent` — the covered list names one component twice.
- `Unauthenticated` — an unsigned 401 answered your request. Do not trust its body.
- `MissingKey` — the signature carries no keyid and you supplied no key. Under the profile, where `keyid` is required, this is the profile's `malformed-signature-input`.

The vectors used to pin all of these names, and they no longer do. `vectors/` still pins fiki's names, but `vectors/keri/` names refusals by the profile's neutral codes (`unknown-key`, `insufficient-coverage`, and so on), because signify-ts reads those files too. The names stay aligned across the ports by deliberate parity rather than by a shared oracle, and §9 of the [profile](keri-profile.md#9-refusals) maps each one to its code.

A mistake in the *call*, as opposed to a defect in the message, is not one of these. Passing both an expected AID and a resolver, a minimum smaller than the profile's, or verifying a response that binds the request's digest against a request with no body are bugs in your code, and each port reports them in its own idiom so that catching fiki's refusals cannot swallow them:

| Language | A refusal of the message | A mistake in the call |
|---|---|---|
| Python | a subclass of `FikiError` | `ValueError`, or `TypeError` for arguments that cannot go together |
| JavaScript | a subclass of `FikiError` | `TypeError` |
| Go | a `*fiki.Error`, discriminated by `Kind` | an error wrapping `fiki.ErrInvalidOptions`, never a `*fiki.Error` |
| Rust | a `fiki::Error`, discriminated by `kind` | a `fiki::Error` of `Kind::InvalidArgument` |
| Java | a `FikiException`, discriminated by `kind()` | `IllegalArgumentException` |
| C# | a `FikiException`, discriminated by `Kind` | `ArgumentException` |

Rust is the exception worth knowing: its call mistakes share the `fiki::Error` type, so match on `kind` rather than treating every `Err` as a refusal.

### Python

```python
from fiki import errors
from fiki.errors import FikiError

def refusal(verify) -> str:
    try:
        verify()
    except errors.UnknownKey as e:
        return f"no key state for {e.keyid}"
    except errors.UnsupportedSigner as e:
        return f"no single key of {e.keyid} signs alone"
    except errors.InsufficientCoverage as e:
        return f"the signature does not cover {e.component}"
    except errors.DuplicateComponent as e:
        return f"the covered list names {e.component} twice"
    except errors.Unauthenticated:
        return "an unsigned 401; its body is not to be trusted"
    except FikiError as e:
        return type(e).__name__
    return "verified"

def group(keyid):
    raise errors.UnsupportedSigner(
        "This AID's key state has no single key that satisfies its threshold.", keyid=keyid
    )
```

### JavaScript

```js
import { FikiError, errors } from '@bakobo/fiki';

try {
  await verifyRequest({ /* ... */ });
} catch (e) {
  if (e instanceof errors.UnknownKey) { /* the resolver has no key state for e.keyid */ }
  else if (e instanceof errors.UnsupportedSigner) { /* e.keyid's key state has no single signer */ }
  else if (e instanceof errors.InsufficientCoverage) { /* the signature does not cover e.component */ }
  else if (e instanceof errors.DuplicateComponent) { /* e.component is listed twice */ }
  else if (e instanceof errors.Unauthenticated) { /* an unsigned 401: do not trust its body */ }
  else if (e instanceof FikiError) { /* any other refusal; e.constructor.name names it */ }
  else throw e;
}
```

### Go

```go
describe := func(err error) string {
	var refusal *fiki.Error
	switch {
	case errors.Is(err, fiki.ErrInvalidOptions):
		return "a mistake in the call, not in the message"
	case errors.As(err, &refusal):
		switch refusal.Kind {
		case fiki.KindUnknownKey:
			return "no key state for " + refusal.Keyid
		case fiki.KindUnsupportedSigner:
			return "no single key of " + refusal.Keyid + " signs alone"
		case fiki.KindInsufficientCoverage:
			return "the signature does not cover " + refusal.Component
		case fiki.KindDuplicateComponent:
			return "the covered list names " + refusal.Component + " twice"
		case fiki.KindUnauthenticated:
			return "an unsigned 401; its body is not to be trusted"
		}
		return refusal.Kind
	}
	return err.Error()
}
```

### Rust

```rust
// Every refusal is an Err(fiki::Error) whose `kind` names the condition and whose
// `detail` carries the offending value, such as the keyid or the missing component.
// The KERI profile added these kinds:
let err = result.unwrap_err();
match err.kind {
    Kind::UnknownKey => {}           // no key is known for the keyid
    Kind::UnsupportedSigner => {}    // the AID's key state has no single signing key
    Kind::InsufficientCoverage => {} // valid, but covers less than the verifier requires
    Kind::DuplicateComponent => {}   // the covered list names a component twice
    Kind::Unauthenticated => {}      // a 401 the server did not sign
    Kind::InvalidArgument => {}      // the call is wrong, not the message
    _ => {}                          // the kinds that predate the profile
}
```

### Java

```java
try {
    Fiki.verifyRequest("POST", url, headers, policy);
} catch (FikiException e) {
    String why = switch (e.kind()) {
        case UnknownKey -> "no key state for " + e.detail();
        case UnsupportedSigner -> "no single signer for " + e.detail();
        case InsufficientCoverage -> "does not cover " + e.detail();
        case DuplicateComponent -> "covers " + e.detail() + " twice";
        case Unauthenticated -> "refused before the agent was known";
        default -> e.kind().name();
    };
}
```

### C#

```csharp
try
{
    verify();
}
catch (FikiException e)
{
    return e.Kind switch
    {
        FikiErrorKind.UnknownKey => "no key state for " + e.KeyId,
        FikiErrorKind.UnsupportedSigner => "no single key of " + e.KeyId + " signs alone",
        FikiErrorKind.InsufficientCoverage => "the signature does not cover " + e.Component,
        FikiErrorKind.DuplicateComponent => "the covered list names " + e.Component + " twice",
        FikiErrorKind.Unauthenticated => "an unsigned 401; its body is not to be trusted",
        _ => e.Kind.ToString(),
    };
}
```

Each carries the value it is about — the keyid or the component — as a field rather than only in the message, so you can log or translate it without parsing prose.

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

heti also speaks a second, older dialect — the legacy KERI flavour that KERIA and signify-ts deploy today, which is not the KERI profile above and which fiki does not verify. That one covers less (no query string, no host, no body) and is not interchangeable with fiki's; which dialect a service accepts is a deployment decision rather than a fallback chain.

## These samples are tested

Every snippet above, the KERI-profile ones included, is exercised by a test in its own port — `py/tests/test_guide.py`, `js/test/guide.test.js`, `go/guide_test.go`, `rust/examples/guide.rs`, `java/.../GuideTest.java`, `csharp/test/Bakobo.Fiki.Tests/GuideTests.cs`. The Python and C# tests also check that the guide shows the tested code line for line. A guide whose code does not run is worse than no guide, so a rename that would break your copy-paste breaks the suite first.

## Which version works with which

Each port versions independently. What tells you two artifacts interoperate is the **vectors format** they declare, not their version numbers — every port exports it as a constant. All six are at vectors format 1 today, and all six also satisfy the KERI profile's set, `vectors/keri/`, at its own format 3. Five ports export that second number as a constant too (`KERI_VECTORS_FORMAT`, or `KeriVectorsFormat` in Go and C#); fiki-py pins it in its test suite but does not yet export it. See the [README](../README.md#versions-and-which-ones-interoperate) for why the two numbers are separate.

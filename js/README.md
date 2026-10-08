# fiki (JavaScript)

[![JavaScript](https://github.com/bakobo/fiki/actions/workflows/ci-js.yml/badge.svg)](https://github.com/bakobo/fiki/actions/workflows/ci-js.yml)

The JavaScript implementation of [fiki](../README.md). Runs in browsers and in Node 20 or newer, with **no dependencies at all** — Ed25519, SHA-256 and randomness come from WebCrypto, and the RFC 8941 structured-fields subset RFC 9421 needs is a few hundred lines in `src/sfv.js`.

## From a fresh clone to passing tests

```sh
cd js
npm test
```

There is nothing to install. The suite runs under `node:test`, and `npm run test:coverage` adds the same 100% branch gate the Python port holds — separately, because Node's coverage thresholds need 22 or newer while the library itself runs on 20. Both commands run the shared `vectors/` at the repository root, so this implementation and the Python one are held to the same bytes.

## Signing a request

```js
import { Key, signRequest } from '@bakobo/fiki';

const key = await Key.generate();          // non-extractable; see below
console.log(key.aid);                      // register this once with whoever you call

const url = 'https://api.example.com/things?limit=1';
const body = new TextEncoder().encode(JSON.stringify({ hello: 'world' }));

const signed = await signRequest({ key, method: 'POST', url, body });
await fetch(url, { method: 'POST', body, headers: signed });
```

By default the signature binds the method, the host, the path, the query string, and a digest of the body. Pass the body wherever you pass the URL: fiki covers a body it is given, or refuses to sign — but it cannot cover one it never sees.

## Verifying a request

```js
import { verifyRequest } from '@bakobo/fiki';

const { aid, keyid, covered } = await verifyRequest({
  method: request.method,
  url: request.url,          // a full URL, or a path plus a Host header
  headers: request.headers,
  body: await request.bytes(),
  maxAge: 300,               // seconds, or null to decline the check
});
```

`keyid` is the keyid exactly as it appeared on the wire, or `null` when the signature had none; `aid` is the identity that vouched for the key — the non-transferable AID of a raw key, the keyid a resolver vouched for, or the AID of `expectedAid`.

`maxAge` has no default and must be given. Both defaults would be wrong: a number guesses at somebody else's clock skew and replay window, and skipping the check silently is the thing the argument exists to prevent. An `expires` the signer declared is enforced either way. `maxAge` and `skew`, when given, are positive whole numbers of seconds.

## What is refused before it is read

`Signature`, `Signature-Input` and `Content-Digest` are each read only up to `MAX_FIELD_BYTES` (8192 bytes, measured before any trimming), `MAX_DICTIONARY_MEMBERS` (16) members, `MAX_INNER_LIST_ITEMS` (64) items in an inner list and `MAX_PARAMETERS` (16) parameters on an item; a header over any of them is that header's malformed error. All four are exported. RFC 8941 is parsed strictly: an integer of more than fifteen digits, a decimal, and a byte sequence that is not canonically padded base64 are refused. A URL whose port is not a number from 0 to 65535, or with anything but `:port` after an IP-literal's `]`, is a `SignatureMismatch` when a covered `@authority` needs it.

The signer refuses, as a `TypeError`, anything it would otherwise serialize into a header that does not belong there: a method that is not an HTTP token, a label that is not an RFC 8941 key, a `keyid`, `nonce` or `tag` outside printable ASCII, a component name that is not a field name, a `created` or `expires` outside 0 to 999999999999999, a header value that is not a string, and a supplied `Content-Digest` the body does not bear out.

## Keys in a browser

`Key.generate()` returns a **non-extractable** key: JavaScript cannot read its private half, so an XSS bug cannot exfiltrate it. Store the object itself in IndexedDB, which persists a `CryptoKey` without ever exposing the bytes. The cost is that the identity belongs to that browser profile — a new device registers a new AID, and `key.seed` throws.

When an identity has to outlive the profile, ask for it:

```js
const key = await Key.generate({ extractable: true });
await save(key.seed);                      // 32 bytes, and now your problem to protect
const same = await Key.fromSeed(await load());
```

The safe shape is the default and the portable one is explicit, because the two runtimes have genuinely different threat models and a browser should not inherit a server's.

## Differences from the Python port

Everything is async. WebCrypto's `sign`, `verify`, `digest` and `importKey` all return promises, so `signRequest`, `signResponse`, `verifyRequest`, `verifyResponse` and the `Key` constructors do too, where the Python versions are synchronous. Names are otherwise the same in camelCase — `signatureBase`, `responseSignatureBase`, `verifyingKey`, `Key.fromSeed`, `key.aid`, `expectedKeyid` — so the two read as one library. Three more differences are deliberate (`this.i` @9enyfktu):

- A `resolve` function may return the key or a promise of it, and verification awaits either, because a KERI resolver usually reads key state from storage or a network.
- The request a response answers is a plain object, `{ method, url, headers, body }`, rather than an exported `Request` class.
- A mistake in the call rather than the message — `expectedAid` together with `resolve`, a `minimum` smaller than the profile's, a missing or non-positive `maxAge`, a response binding the request's digest verified without the request body, and everything the signer refuses above — is a `TypeError`. Python raises `TypeError` for some of these and `ValueError` for others; JavaScript has no `ValueError`. None of them is a `FikiError`.

URLs are cleaned as Python's `urlsplit` cleans them — leading control characters and spaces stripped, TAB, CR and LF removed anywhere — and then split as sent rather than parsed with `new URL`, which normalizes the path that RFC 9421 and the KERI profile sign unnormalized (`this.i` @90y0gsfx).

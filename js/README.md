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

const { aid, covered } = await verifyRequest({
  method: request.method,
  url: request.url,          // a full URL, or a path plus a Host header
  headers: request.headers,
  body: await request.bytes(),
  maxAge: 300,               // seconds, or null to decline the check
});
```

`maxAge` has no default and must be given. Both defaults would be wrong: a number guesses at somebody else's clock skew and replay window, and skipping the check silently is the thing the argument exists to prevent. An `expires` the signer declared is enforced either way.

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

Everything is async. WebCrypto's `sign`, `verify`, `digest` and `importKey` all return promises, so `signRequest`, `verifyRequest` and the `Key` constructors do too, where the Python versions are synchronous. Names are otherwise the same in camelCase — `signatureBase`, `verifyingKey`, `Key.fromSeed`, `key.aid` — so the two read as one library.

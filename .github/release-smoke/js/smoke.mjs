// Release smoke test for @bakobo/fiki, run against the package INSTALLED FROM npm, never the
// source. The same four checks as every port's smoke test (docs/releasing.md): a plain vector, a
// plain round trip, a KERI vector through a resolver, and a KERI round trip under a caller-chosen
// AID keyid. Usage: node smoke.mjs <vectors-dir>
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Key, REQUEST_MINIMUM, signRequest, verifyRequest } from '@bakobo/fiki';

const vectors = process.argv[2];
const load = (...parts) => JSON.parse(readFileSync(join(vectors, ...parts), 'utf8'));
const b64url = (text) => new Uint8Array(Buffer.from(text, 'base64url'));
const hex = (text) => new Uint8Array(Buffer.from(text, 'hex'));

function check(name, got, want) {
  if (got !== want) {
    console.error(`FAIL ${name}: got ${got}, want ${want}`);
    process.exit(1);
  }
  console.log(`ok   ${name}`);
}

const plain = load('accepts.json').cases.find((c) => c.id === 'default-covered-get');
let verdict = await verifyRequest({
  method: plain.method, url: plain.url, headers: plain.headers, body: null, maxAge: null, now: plain.now,
  authorities: plain.authorities,
});
check('plain vector', verdict.aid, plain.aid);

const key = await Key.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => i));
let url = 'https://api.example.com/things?limit=1';
const body = new TextEncoder().encode('{"hello": "world"}');
let headers = await signRequest({ key, method: 'POST', url, body });
verdict = await verifyRequest({ method: 'POST', url, headers, body, maxAge: 300, expectedAid: key.aid,
  authorities: ['api.example.com'] });
check('plain round trip', verdict.aid, key.aid);

const keri = load('keri', 'requests.json');
const table = new Map(keri.keys.map((k) => [k.keyid, k]));
const resolve = async (keyid) => (table.has(keyid) ? b64url(table.get(keyid).effective_key) : null);

const kase = keri.cases.find((c) => c.id === 'get-with-query');
verdict = await verifyRequest({
  method: kase.request.method, url: kase.request.url, headers: kase.request.headers, body: null,
  maxAge: keri.policy.max_age, skew: keri.policy.skew, now: kase.now, resolve, minimum: REQUEST_MINIMUM,
  authorities: kase.policy?.authorities ?? null,
});
check('KERI vector', verdict.aid, kase.expected.keyid);

const controller = table.get(kase.expected.keyid);
const signer = await Key.fromSeed(hex(controller.seed_hex));
url = 'https://keria.example.com/identifiers?type=rot';
headers = await signRequest({ key: signer, method: 'GET', url, keyid: controller.keyid, minimum: REQUEST_MINIMUM });
verdict = await verifyRequest({ method: 'GET', url, headers, body: null, maxAge: 300, resolve, minimum: REQUEST_MINIMUM,
  authorities: null });
check('KERI round trip', verdict.aid, controller.keyid);

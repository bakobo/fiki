// The KERI profile's vector set, `vectors/keri/` (`this.i` @8vwrexxc, @9enyfktu).
//
// A separate contract from the shared `vectors/`: its own format number, refusals named by the
// profile's neutral section 9 codes rather than fiki's class names. The files are read in place
// from the repository root, never copied, so this port and fiki-py are held to the same bytes.
//
// fiki-py's driver imports the generator's resolver, well-formedness rule and policy-applying
// verifier from vectors/keri/generate.py (@4tkkp50h). A JavaScript driver cannot import Python,
// so the class-to-code table is read out of the generator's own text rather than copied, and the
// resolver is rebuilt here from the keys_rule each file states. That resolver is authoritative: it
// derives a non-transferable B keyid's key from the prefix, looks every transferable keyid up in
// the table, answers null for a well-formed AID it has no key state for, raises UnsupportedSigner
// for a key state with no single effective signer, and refuses a keyid that is not an AID at all.
// It never decodes a D keyid as a key, which is exactly what one of the vectors is there to catch.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  FikiError,
  KERI_VECTORS_FORMAT,
  Key,
  errors,
  responseSignatureBase,
  signRequest,
  signatureBase,
  verifyRequest,
  verifyResponse,
  verifyingKey,
} from '../src/index.js';
import { parseDictionary, serializeInnerList } from '../src/sfv.js';

const KERI = new URL('../../vectors/keri/', import.meta.url);
const FILES = ['rfc9421.json', 'requests.json', 'responses.json', 'refusals.json', 'legacy.json'];

const load = (name) => JSON.parse(readFileSync(new URL(name, KERI), 'utf8'));

// The generator's CODES table, read from its source: the one place the class-to-code mapping lives.
const CODES = (() => {
  const source = readFileSync(new URL('generate.py', KERI), 'utf8');
  const block = source.match(/^CODES = \{\n([\s\S]*?)\n\}/m)[1];
  return Object.fromEntries([...block.matchAll(/"(\w+)": "([a-z-]+)"/g)].map((m) => [m[1], m[2]]));
})();

const fromHex = (hex) => Uint8Array.from(hex.match(/../g).map((b) => parseInt(b, 16)));
const fromB64Url = (text) => new Uint8Array(Buffer.from(text, 'base64url'));
const toBase64 = (bytes) => Buffer.from(bytes).toString('base64');
const bodyOf = (message) => (message.body === null ? null : new TextEncoder().encode(message.body));
const asRequest = (message) => ({
  method: message.method,
  url: message.url,
  headers: message.headers,
  body: bodyOf(message),
});

/** keys_rule's well-formedness test: 44 characters, B, D or E, the canonical spelling of 32 bytes. */
function wellFormedAid(keyid) {
  if (keyid.length !== 44 || !'BDE'.includes(keyid[0])) return false;
  if (!/^[A-Za-z0-9_-]{43}$/.test(keyid.slice(1))) return false;
  const decoded = Buffer.from('A' + keyid.slice(1), 'base64url');
  const canonical = Buffer.concat([Buffer.alloc(1), decoded.subarray(1)]).toString('base64url');
  return decoded.length === 33 && keyid[0] + canonical.slice(1) === keyid;
}

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** The same 32 key bytes, spelled with a non-zero bit in the pad byte the code replaces. */
const paddingBitAlias = (aid) => aid[0] + ALPHABET[ALPHABET.indexOf(aid[1]) ^ 0b010000] + aid.slice(2);

/** What a KERI verifier's key lookup does, for a keys table: authoritative, never a decode. */
function resolver(keys) {
  const table = new Map(keys.filter((e) => e.kind === 'transferable').map((e) => [e.keyid, e]));
  // Async on purpose: a real resolver reads key state from storage, and verify awaits it.
  return async (keyid) => {
    if (!wellFormedAid(keyid)) throw new errors.MalformedKey(`"${keyid}" is not a well-formed AID.`, { keyid });
    if (keyid.startsWith('B')) return verifyingKey(keyid);
    const entry = table.get(keyid);
    if (entry === undefined) return null;
    if (entry.effective_key === null) {
      throw new errors.UnsupportedSigner(
        `The key state of "${keyid}" has no single key that satisfies its threshold.`,
        { keyid },
      );
    }
    return fromB64Url(entry.effective_key);
  };
}

/** Verify a case's message under the file's policy extended by the case's, as a KERI verifier. */
function run(request, response, { now, policy, keys }) {
  const common = {
    maxAge: policy.max_age,
    skew: policy.skew,
    now,
    resolve: resolver(keys),
    expectedKeyid: policy.expected_keyid ?? null,
  };
  if (response) {
    return verifyResponse({
      status: response.status,
      headers: response.headers,
      body: bodyOf(response),
      request: asRequest(request),
      minimum: policy.response_minimum,
      ...common,
    });
  }
  return verifyRequest({
    method: request.method,
    url: request.url,
    headers: request.headers,
    body: bodyOf(request),
    minimum: policy.request_minimum,
    authorities: policy.authorities ?? null,
    ...common,
  });
}

const runCase = (c, data) =>
  run(c.request, c.response, { now: c.now, policy: { ...data.policy, ...(c.policy ?? {}) }, keys: data.keys });

// A covered component in its RFC 8941 serialized form, which is how the files spell every one.
const serialized = (covered) => covered.map((spec) => (spec.startsWith('"') ? spec : `"${spec}"`));

/** The base a signer builds from the message's own Signature-Input, and the signature over it. */
async function expectedBase(request, response, keys) {
  const message = response ?? request;
  const [inner] = parseDictionary(message.headers['Signature-Input']).values();
  const covered = inner.items.map((item) => serializeInnerList({ items: [item], params: new Map() }).slice(1, -1));
  const p = Object.fromEntries(inner.params);
  const args = { covered, created: p.created, keyid: p.keyid, alg: p.alg, expires: p.expires, nonce: p.nonce, tag: p.tag };
  const base = response
    ? responseSignatureBase({ status: response.status, headers: response.headers, request: asRequest(request), ...args })
    : signatureBase({ method: request.method, url: request.url, headers: request.headers, ...args });
  // Ed25519 is deterministic, so the signer in the keys table reproduces the message's signature.
  const entry = keys.find((e) => e.keyid === p.keyid);
  const signature = toBase64(await (await Key.fromSeed(fromHex(entry.seed_hex))).sign(base));
  return [new TextDecoder().decode(base), signature];
}

// --- the files themselves ---

describe('the KERI vectors format', () => {
  for (const name of FILES) {
    it(`${name} is the contract this port satisfies`, () => {
      // The same guard @4fhrre0m gives the shared set, against its own number.
      const data = load(name);
      assert.equal(data.keri_vectors_format, KERI_VECTORS_FORMAT);
      assert.equal(KERI_VECTORS_FORMAT, 2);
      assert.ok(!('vectors_format' in data));
      assert.ok(data.cases.length > 0);
    });

    it(`${name} names the published profile it pins`, () => {
      // The contract is a document anyone can read, beside these files (@997vxdu7).
      const { profile } = load(name);
      assert.equal(profile.version, 1);
      assert.equal(profile.where, 'https://github.com/bakobo/fiki/blob/main/docs/keri-profile.md');
      const doc = readFileSync(new URL('../../docs/keri-profile.md', import.meta.url), 'utf8');
      assert.ok(doc.startsWith(`# ${profile.title}\n\nVersion 1, `));
    });
  }

  for (const name of ['requests.json', 'responses.json', 'refusals.json']) {
    it(`${name} states the policy it assumes`, () => {
      const { policy } = load(name);
      assert.equal(policy.max_age, 300);
      assert.equal(policy.skew, 60);
      assert.deepEqual(policy.request_minimum, ['"@method"', '"@path"', '"@query"']);
      assert.deepEqual(policy.response_minimum, ['"@status"', '"@method";req', '"@path";req', '"@query";req']);
    });

    it(`${name}'s keys table agrees with its seeds and key states`, async () => {
      // A table entry that disagrees with its own seed would make every case using it a lie.
      const data = load(name);
      assert.ok(data.keys_rule);
      for (const entry of data.keys) {
        assert.ok(wellFormedAid(entry.keyid), entry.keyid);
        const signer = await Key.fromSeed(fromHex(entry.seed_hex));
        const raw = verifyingKey(signer.aid);
        if (entry.kind === 'non-transferable') {
          assert.equal(entry.keyid, signer.aid);
          continue;
        }
        const state = entry.key_state.keys.map((k) => {
          assert.ok(k.startsWith('D') && k.length === 44);
          return toBase64(fromB64Url('A' + k.slice(1)).slice(1));
        });
        if (entry.effective_key === null) {
          assert.equal(toBase64(raw), state[0]);
        } else {
          assert.deepEqual(fromB64Url(entry.effective_key), raw);
          assert.ok(state.includes(toBase64(raw)));
        }
      }
    });
  }

  it('reads the class-to-code table out of the generator', () => {
    assert.equal(CODES.MissingSignature, 'missing-signature');
    assert.equal(CODES.SignatureTooOld, 'signature-stale');
    assert.equal(Object.keys(CODES).length, 23);
  });

  it('refuses near misses under the well-formedness rule', () => {
    assert.ok(!wellFormedAid('E' + '!'.repeat(43)));
    assert.ok(!wellFormedAid('A' + 'A'.repeat(43)));
    assert.ok(!wellFormedAid('not-an-aid'));
    // bakobo/fiki#4: a B keyid spelled with a non-zero pad bit would alias the same key.
    for (const entry of load('requests.json').keys) {
      assert.ok(wellFormedAid(entry.keyid));
      assert.ok(!wellFormedAid(paddingBitAlias(entry.keyid)));
    }
  });

  it('names a profile code in every refusal, and exercises every profile code', () => {
    const data = load('refusals.json');
    const named = new Set(data.cases.map((c) => c.error));
    assert.deepEqual([...named].sort(), [...data.codes].sort());
    for (const code of Object.values(CODES)) assert.ok(named.has(code), code);
  });

  it('gives every fiki error class a profile code', () => {
    // The same totality heti's boundary test enforces (@8zw78n0v), against the profile's codes.
    const classes = Object.values(errors).filter((c) => typeof c === 'function' && c.prototype instanceof FikiError);
    assert.deepEqual(classes.map((c) => c.name).sort(), Object.keys(CODES).sort());
  });

  it('names refusals by neutral codes rather than fiki class names', () => {
    for (const c of load('refusals.json').cases) {
      assert.equal(c.error, c.error.toLowerCase());
      assert.ok(!(c.error in CODES));
    }
  });
});

// --- RFC 9421 B.2.6, which anchors the set to something no Bakobo party wrote ---

describe('RFC 9421 B.2.6', () => {
  it("reproduces the RFC's own base and signature", async () => {
    const [c] = load('rfc9421.json').cases;
    const base = signatureBase({
      method: c.request.method,
      url: c.request.url,
      headers: c.request.headers,
      covered: c.covered,
      created: c.created,
      keyid: c.keyid,
    });
    assert.equal(new TextDecoder().decode(base), c.expected.base);
    const key = await Key.fromSeed(fromHex(c.seed_hex));
    assert.equal(toBase64(await key.sign(base)), c.expected.signature);
  });
});

// --- the accept cases ---

describe('KERI requests every implementation must accept', () => {
  const data = load('requests.json');
  for (const c of data.cases) {
    it(c.id, async () => {
      const verdict = await runCase(c, data);
      assert.equal(verdict.keyid, c.expected.keyid);
      assert.deepEqual(serialized(verdict.covered), c.expected.covered);
      assert.deepEqual(await expectedBase(c.request, null, data.keys), [c.expected.base, c.expected.signature]);
    });
  }

  it('marks the sha-512 cases verify-only', () => {
    const ids = new Set(data.cases.map((c) => c.id));
    for (const id of data.verify_only) assert.ok(ids.has(id));
    for (const c of data.cases) {
      const digest = c.request.headers['Content-Digest'] ?? '';
      if ((digest && !digest.startsWith('sha-256=')) || digest.includes(',')) assert.ok(data.verify_only.includes(c.id));
    }
  });
});

describe('KERI responses every client must accept', () => {
  const data = load('responses.json');
  for (const c of data.cases) {
    it(c.id, async () => {
      await run(c.request, null, { now: c.now, policy: data.policy, keys: data.keys });
      const verdict = await runCase(c, data);
      assert.equal(verdict.keyid, c.expected.keyid);
      assert.deepEqual(serialized(verdict.covered), c.expected.covered);
      assert.deepEqual(await expectedBase(c.request, c.response, data.keys), [c.expected.base, c.expected.signature]);
    });
  }
});

// --- the refusals ---

describe('KERI messages every implementation must refuse', () => {
  const data = load('refusals.json');
  for (const c of data.cases) {
    it(`${c.id} (${c.error})`, async () => {
      // Each case has one defect and so one correct code under the profile's section 9 order.
      if (c.verified_by_fiki === false) {
        // Carried as data (@4tkkp50h): fiki has no legacy mode to detect it with.
        assert.equal(c.error, 'mode-mismatch');
        assert.ok(c.why);
        return;
      }
      const attempt =
        c.kind === 'sign-request'
          ? async () =>
              signRequest({
                key: await Key.fromSeed(fromHex(c.seed_hex)),
                method: c.request.method,
                url: c.request.url,
                headers: c.request.headers,
                body: bodyOf(c.request),
                covered: c.covered,
                keyid: c.keyid,
                minimum: data.policy.request_minimum,
              })
          : () => runCase(c, data);
      await assert.rejects(attempt, (err) => {
        assert.ok(err instanceof FikiError, `expected a FikiError, got ${err}`);
        assert.equal(CODES[err.constructor.name], c.error, `${err.constructor.name}: ${err.message}`);
        return true;
      });
    });
  }
});

// --- legacy material, which fiki carries and never verifies (@8vwrexxc) ---

describe('the legacy material', () => {
  const data = load('legacy.json');

  it('carries what a legacy verifier needs, and its provenance', () => {
    for (const c of data.cases) {
      assert.ok(['WebOfTrust/keria', 'WebOfTrust/signify-ts'].includes(c.source.repo));
      assert.equal(c.source.commit.length, 40);
      assert.ok(c.source.file && c.source.lines);
      for (const field of ['kind', 'method', 'path', 'headers', 'key', 'keyid', 'created']) {
        assert.ok(field in c, field);
      }
      assert.ok(c.headers['Signature-Input'].startsWith('signify='));
      assert.ok(c.headers.Signature.startsWith('indexed="?0";signify="0B'));
    }
  });

  for (const c of data.cases) {
    it(`${c.id}'s signature verifies over its stated base`, async () => {
      // Transcription check only: pure Ed25519 over the base the file states, no legacy logic.
      const signature = c.headers.Signature.split('signify="')[1].replace(/"$/, '');
      const rawSignature = fromB64Url('AA' + signature.slice(2)).slice(2);
      const rawKey = fromB64Url('A' + c.key.slice(1)).slice(1);
      const key = await crypto.subtle.importKey('raw', rawKey, { name: 'Ed25519' }, false, ['verify']);
      assert.ok(await crypto.subtle.verify({ name: 'Ed25519' }, key, rawSignature, new TextEncoder().encode(c.base)));
    });
  }
});

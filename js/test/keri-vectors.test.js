// The KERI profile's vector set, `vectors/keri/` (`this.i` @8vwrexxc, @9enyfktu).
//
// A separate contract from the shared `vectors/`: its own format number, refusals named by the
// profile's neutral section 9 codes rather than fiki's class names. The files are read in place
// from the repository root, never copied, so this port and fiki-py are held to the same bytes.
//
// The class-to-code table is read out of the generator's own text rather than copied, and the
// resolver is written here from the files alone. That resolver is authoritative (@6g9zjsv9) and
// knows key state alone (@7w7nv94j): it looks every keyid up in the table, answers null for a
// keyid it has no key state for, and raises UnsupportedSigner for a key state with no single
// effective signer. It knows nothing of B keyids: since keri_vectors_format 8 the library takes
// their key from the prefix and never asks (@37rktct3), and the case whose B keyid the table does
// not list would fail if it did. It never decodes a D keyid as a key, which is exactly what one of
// the vectors is there to catch, and it carries no well-formedness check: a keyid that is not an
// AID, or a weak B key, is fiki's to refuse, so the refusal vectors for them test the library
// rather than this file. The well-formedness rule below checks the files' own keys tables, never a
// keyid under test.

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

// How many cases of each file this driver ran, against the number pinned in CASES at the end of
// the file (tick 7xbw, T8): an emptied cases array passed every driver before.
const ran = new Map();
const tally = (name) => ran.set(name, (ran.get(name) ?? 0) + 1);

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

/** keys_rule's well-formedness test, for the codes the keys tables use: 44 characters, B, D or E,
 * the canonical spelling of 32 bytes. keys_rule admits every PreDex code (@37rktct3); the tables
 * use only these three, and the library's own test of the rest is test/profile-v1-2.test.js. */
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

/** A KERI verifier's key lookup over a file's keys table: key state, and nothing else. */
function resolver(keys) {
  const table = new Map(keys.filter((e) => e.kind === 'transferable').map((e) => [e.keyid, e]));
  // Async on purpose: a real resolver reads key state from storage, and verify awaits it.
  return async (keyid) => {
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
    // fiki's clock is whole seconds, and the profile rounds a fractional one down (section 6).
    now: Math.floor(now),
    resolve: resolver(keys),
    // Absent from a policy means the explicit decline, which verifyResponse requires be stated.
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

/** The key a signature is checked with when a base is rebuilt: a B prefix's own, else the table's. */
async function keyFor(keyid, keys) {
  if (keyid.startsWith('B')) return fromB64Url('A' + keyid.slice(1)).slice(1);
  const key = await resolver(keys)(keyid);
  assert.ok(key, `no key resolves for ${keyid}`);
  return key;
}

/** Whether `signature`, standard base64, verifies over `base` under the raw key. */
async function verifies(raw, signature, base) {
  const key = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
  return crypto.subtle.verify({ name: 'Ed25519' }, key, new Uint8Array(Buffer.from(signature, 'base64')), base);
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
  const signature = message.headers.Signature.split('=').slice(1).join('=').replace(/^:|:$/g, '');
  assert.ok(await verifies(await keyFor(p.keyid, keys), signature, base), 'the signature does not verify over the rebuilt base');
  return [new TextDecoder().decode(base), signature];
}

/** A weak key reaches the signature check as fiki's own raw keyid, and a resolver returning it
 * for `keyid` is refused as MalformedKey, by the library's subgroup check, before any signature. */
async function weakKeyIsRefusedAsResolved(keyid, weak) {
  const signer = await Key.fromSeed(new Uint8Array(32));
  const signed = async (id) => {
    const args = { key: signer, method: 'GET', url: 'https://keria.example.com/x', headers: {}, created: 1700000000, keyid: id };
    return { method: 'GET', url: args.url, body: null, headers: await signRequest(args) };
  };
  const common = { maxAge: null, authorities: null, minimum: null };
  await assert.rejects(
    async () => verifyRequest({ ...(await signed(Buffer.from(weak).toString('base64url'))), ...common }),
    errors.SignatureMismatch,
  );
  await assert.rejects(
    async () => verifyRequest({ ...(await signed(keyid)), ...common, resolve: (k) => (k === keyid ? weak : null) }),
    (e) => e instanceof errors.MalformedKey && e.keyid === keyid,
  );
}

// --- the files themselves ---

describe('the KERI vectors format', () => {
  for (const name of FILES) {
    it(`${name} is the contract this port satisfies`, () => {
      // The same guard @4fhrre0m gives the shared set, against its own number.
      const data = load(name);
      assert.equal(data.keri_vectors_format, KERI_VECTORS_FORMAT);
      assert.equal(KERI_VECTORS_FORMAT, 8);
      assert.ok(!('vectors_format' in data));
      assert.ok(data.cases.length > 0);
    });

    it(`${name} names the published profile it pins`, () => {
      // The contract is a document anyone can read, beside these files (@997vxdu7).
      const { profile } = load(name);
      assert.equal(profile.version, '1.2');
      assert.equal(profile.where, 'https://github.com/bakobo/fiki/blob/keri-profile-v1.2/docs/keri-profile.md');
      const doc = readFileSync(new URL('../../docs/keri-profile.md', import.meta.url), 'utf8');
      assert.ok(doc.startsWith(`# ${profile.title}\n\nVersion 1.2, ${profile.date}.`));
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
        if (entry.weak_key) {
          // A key no seed yields, there to be refused as it is resolved (profile R1): the key
          // state's one key, which fiki's own raw-keyid lens takes as a key (@5r75ff4m) and the
          // library's subgroup check refuses under a resolver.
          assert.deepEqual(state, [toBase64(fromB64Url(entry.effective_key))]);
          await weakKeyIsRefusedAsResolved(entry.keyid, fromB64Url(entry.effective_key));
          continue;
        }
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
    tally('rfc9421.json');
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
      tally('requests.json');
      if (c.verified_by_fiki === false) {
        // Carried as data: fiki's own vectors refuse missing padding (@2g4xxev9, @7ve9r2c6). The
        // base and signature are still the ones the message carries.
        assert.ok(c.why && data.verify_only.includes(c.id));
        const signature = c.expected.signature + '='.repeat((4 - (c.expected.signature.length % 4)) % 4);
        assert.ok(await verifies(await keyFor(c.expected.keyid, data.keys), signature, new TextEncoder().encode(c.expected.base)));
        return;
      }
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
      tally('responses.json');
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
      tally('refusals.json');
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
      if (c.source.repo === 'bakobo/fiki') {
        // Generated, not pinned (keri_vectors_format 7): the seed reproduces the signature.
        assert.equal(c.source.file, 'vectors/keri/generate.py');
        assert.ok(c.source.generated && c.seed_hex && 'key_state' in c && 'sufficient_keys' in c);
      } else {
        assert.ok(['WebOfTrust/keria', 'WebOfTrust/signify-ts'].includes(c.source.repo));
        assert.equal(c.source.commit.length, 40);
        assert.ok(c.source.file && c.source.lines);
        assert.ok(!('key_state' in c) && !('error' in c));
      }
      for (const field of ['kind', 'method', 'path', 'headers', 'key', 'keyid', 'created']) {
        assert.ok(field in c, field);
      }
      assert.ok(c.headers['Signature-Input'].startsWith('signify='));
      assert.ok(c.headers.Signature.startsWith('indexed="?0";signify="0B'));
    }
  });

  for (const c of data.cases) {
    it(`${c.id}'s signature verifies over its stated base`, async () => {
      tally('legacy.json');
      // Transcription check only: pure Ed25519 over the base the file states, no legacy logic.
      const signature = c.headers.Signature.split('signify="')[1].replace(/"$/, '');
      const rawSignature = fromB64Url('AA' + signature.slice(2)).slice(2);
      const rawKey = fromB64Url('A' + c.key.slice(1)).slice(1);
      const key = await crypto.subtle.importKey('raw', rawKey, { name: 'Ed25519' }, false, ['verify']);
      assert.ok(await crypto.subtle.verify({ name: 'Ed25519' }, key, rawSignature, new TextEncoder().encode(c.base)));
    });

    it(`${c.id}'s outcome agrees with its key state`, async () => {
      // Profile section 8 at version 1.2: any key that alone satisfies the threshold may sign.
      // fiki has no legacy verifier, so this checks the data: the key state reduces to the
      // sufficient_keys the case states, and the error follows from them and from who signed.
      if (!('key_state' in c)) return; // pinned from KERIA or signify-ts: accepted under its key
      if (c.key_state === null) {
        assert.equal(c.sufficient_keys, null);
        assert.equal(c.error, 'unknown-key');
        return;
      }
      const { keys, threshold } = c.key_state;
      // Written out here rather than read from the generator, which made the case with its own.
      const weight = (w) => { const [n, d = '1'] = w.split('/'); return Number(n) / Number(d); };
      const alone = typeof threshold === 'string'
        ? (parseInt(threshold, 16) === 1 ? keys : [])
        : keys.filter((_, i) => weight(threshold[i]) >= 1);
      const raw = (qb64) => Buffer.from(fromB64Url('A' + qb64.slice(1)).slice(1)).toString('base64url');
      assert.deepEqual(c.sufficient_keys, alone.map(raw));
      const signature = c.headers.Signature.split('signify="')[1].replace(/"$/, '');
      const rawSignature = fromB64Url('AA' + signature.slice(2)).slice(2);
      if (alone.length === 0) {
        assert.equal(c.error, 'unsupported-signer');
      } else if (c.error === 'signature-mismatch') {
        assert.ok(!alone.includes(c.key));
        for (const key of c.sufficient_keys) {
          const imported = await crypto.subtle.importKey('raw', fromB64Url(key), { name: 'Ed25519' }, false, ['verify']);
          assert.ok(!(await crypto.subtle.verify({ name: 'Ed25519' }, imported, rawSignature, new TextEncoder().encode(c.base))));
        }
      } else {
        // Accepted, or a header refused before any key is tried, whose key state would accept.
        assert.ok(alone.includes(c.key));
        assert.ok(!('error' in c) || load('refusals.json').codes.includes(c.error), c.error);
      }
    });
  }
});

// Read once from the files at keri_vectors_format 8, never at test time, so a file that loses cases fails.
const CASES = {
  'legacy.json': 12,
  'refusals.json': 78,
  'requests.json': 25,
  'responses.json': 4,
  'rfc9421.json': 1,
};

describe('the driver ran every case', () => {
  it('pins every file', () => assert.deepEqual(Object.keys(CASES).sort(), [...FILES].sort()));
  for (const [name, count] of Object.entries(CASES)) {
    it(`${name} holds ${count} cases and all of them ran`, () => {
      assert.equal(load(name).cases.length, count);
      assert.equal(ran.get(name), count);
    });
  }
});

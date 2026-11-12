// Ed25519 keys, whose public half *is* the identifier (`this.i` @07wstqk7, @2q9gv70t).
//
// Everything here goes through WebCrypto, which is why the port needs no crypto dependency and
// why every method is async — that asymmetry with the Python port is forced by the platform
// rather than chosen.
//
// Keys are NON-EXTRACTABLE by default. A browser key that JavaScript cannot read cannot be
// exfiltrated by an XSS bug, which is the dominant threat for a browser-held signing key; the
// cost is that the identity is bound to one browser profile and a new device registers a new AID.
// `generate({extractable: true})` is the opt-in for a caller who needs a portable identity, and
// `seed()` throws rather than returning nothing when the key cannot produce one.

import { equal, fromBase64Url, toBase64Url } from './bytes.js';
import { MalformedKey } from './errors.js';
import { quoted } from './base.js';
import { DOES_NOT_DERIVE, readOpenssh, refusePrivate } from './openssh.js';

// CESR's Ed25519N (non-transferable Ed25519 verification key). fiki decodes this code and no
// other: a parser that handles one fixed-length code can only ever be narrower than a full CESR
// implementation, which is the safe direction for a differential.
const CODE = 'B';
const RAW_LEN = 32;
const QB64_LEN = 44;

// WebCrypto refuses a raw private key and accepts PKCS#8, and a PKCS#8 Ed25519 private key is a
// fixed DER prefix followed by the 32-byte seed — so this is a concatenation rather than an
// ASN.1 encoder.
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

const ALGORITHM = { name: 'Ed25519' };

/** Render a raw 32-byte Ed25519 public key as a non-transferable AID. */
export function toAid(raw) {
  const padded = new Uint8Array(RAW_LEN + 1);
  padded.set(raw, 1);
  return CODE + toBase64Url(padded).slice(1);
}

// libsodium's has_small_order blocklist (tick 27eo, `this.i` @4wcwlqd6): the encodings of the
// points whose order divides 8, plus the non-canonical y = p and y = p + 1, compared with the sign
// bit of the last byte masked. Under such a key a fixed signature verifies over any message, so it
// binds nothing; test/small-order.test.js decodes every entry and checks its order.
const hex = (text) => Uint8Array.from(text.match(/../g), (pair) => parseInt(pair, 16));
export const SMALL_ORDER = Object.freeze([
  hex('00'.repeat(32)), // order 4
  hex('01' + '00'.repeat(31)), // the identity, order 1
  hex('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'), // order 8
  hex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'), // order 8
  hex('ec' + 'ff'.repeat(30) + '7f'), // p - 1, order 2
  hex('ed' + 'ff'.repeat(30) + '7f'), // p, a non-canonical 0, order 4
  hex('ee' + 'ff'.repeat(30) + '7f'), // p + 1, a non-canonical 1, the identity
]);

const smallOrder = (raw) =>
  SMALL_ORDER.some((entry) => entry.every((byte, i) => (i === RAW_LEN - 1 ? raw[i] & 0x7f : raw[i]) === byte));

// RFC 8032 section 5.1.3's decoding, as far as deciding whether 32 bytes ARE a point: y below p,
// x squared = (y^2 - 1) / (d y^2 + 1) a square mod p, and no sign bit on an x of zero. BigInt rather
// than a dependency, because this is a yes-or-no question and needs no curve arithmetic beyond it.
const P = 2n ** 255n - 19n;
const mod = (a) => ((a % P) + P) % P;
function power(base, exponent) {
  let result = 1n;
  for (let b = mod(base), e = exponent; e > 0n; e >>= 1n, b = mod(b * b)) if (e & 1n) result = mod(result * b);
  return result;
}
const D = mod(-121665n * power(121666n, P - 2n));

const SQRT_M1 = power(2n, (P - 1n) / 4n);

/** The point `raw` encodes as [x, y], or null when it is not the canonical encoding of one. */
function decodePoint(raw) {
  let y = 0n;
  for (let i = RAW_LEN - 1; i >= 0; i -= 1) y = (y << 8n) | BigInt(raw[i]);
  const sign = y >> 255n;
  y &= (1n << 255n) - 1n;
  if (y >= P) return null;
  const x2 = mod((y * y - 1n) * power(D * y * y + 1n, P - 2n));
  // RFC 8032's square root: a candidate, times sqrt(-1) when its square is -x2, and no point at
  // all when neither squares to x2.
  let x = power(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1);
  if (mod(x * x - x2) !== 0n) return null;
  // x of zero has one encoding only, with the sign bit clear.
  if (x === 0n && sign === 1n) return null;
  return [(x & 1n) === sign ? x : mod(-x), y];
}

// The order of Ed25519's prime-order subgroup, RFC 8032 section 5.1's L.
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/** RFC 8032 section 5.1.4's addition, on points in extended coordinates (X, Y, Z, T). */
function addExtended([x1, y1, z1, t1], [x2, y2, z2, t2]) {
  const a = mod((y1 - x1) * (y2 - x2));
  const b = mod((y1 + x1) * (y2 + x2));
  const c = mod(t1 * 2n * D * t2);
  const d = mod(z1 * 2n * z2);
  const [e, f, g, h] = [b - a, d - c, d + c, b + a];
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}

/** True when [L]P is the identity, so P lies in the prime-order subgroup (@37rktct3).
 *
 * A point of small order is not caught here, since the identity is one; the blocklist runs first.
 * What this adds is the mixed-order point, a subgroup point plus a torsion component, which
 * libsodium's crypto_core_ed25519_is_valid_point refuses and keripy follows.
 */
function primeOrder([x, y]) {
  let total = [0n, 1n, 1n, 0n];
  let step = [x, y, 1n, mod(x * y)];
  for (let n = L; n > 0n; n >>= 1n) {
    if (n & 1n) total = addExtended(total, step);
    step = addExtended(step, step);
  }
  return total[0] === 0n && total[1] === total[2];
}

/** Refuse a 32-byte public key that is not a canonical point, or is of small order (27eo).
 *
 * With `subgroup`, which is how a key named by an AID is read (KERI profile R1, @37rktct3), a point
 * outside the prime-order subgroup is refused too; fiki's own raw keyid accepts one (@5r75ff4m).
 */
export function checkKey(raw, keyid, { subgroup = false } = {}) {
  // An empty keyid names no one, for a caller that must not echo what it was given (@0mvgkwnl).
  const subject = keyid ? `The key for ${quoted(keyid)}` : 'The key given';
  const point = decodePoint(raw);
  if (point === null) {
    throw new MalformedKey(
      `${subject} is not the canonical encoding of a point on the Ed25519 curve, so ` +
        'it is not a key fiki will verify with.',
      { keyid },
    );
  }
  if (smallOrder(raw)) {
    throw new MalformedKey(
      `${subject} is a small-order Ed25519 point, under which a signature can be ` +
        'forged for any message, so it is not a key fiki will verify with.',
      { keyid },
    );
  }
  if (subgroup && !primeOrder(point)) {
    throw new MalformedKey(
      `${subject} is a point of mixed order, outside the prime-order subgroup every honest key ` +
        'lies in, so no signature is checked against it.',
      { keyid },
    );
  }
  return raw;
}

/** Recover the raw 32-byte Ed25519 public key from a non-transferable AID. */
export function verifyingKey(aid) {
  if (typeof aid !== 'string' || aid.length !== QB64_LEN || !aid.startsWith(CODE)) {
    throw new MalformedKey(
      `A non-transferable AID is ${QB64_LEN} characters beginning with "${CODE}"; this one is ` +
        `${typeof aid === 'string' ? aid.length : 0} characters and begins with ${quoted(String(aid).slice(0, 1))}.`,
      { keyid: aid },
    );
  }
  // Strict rather than lenient: "=" is inside base64's alphabet, so a 44-character string of the
  // right shape can still decode short, and a decoder is exactly the place a quiet shortfall
  // turns into somebody else's exception.
  if (!/^[A-Za-z0-9\-_]{44}$/.test(aid)) {
    throw new MalformedKey(`The AID ${quoted(aid)} is not valid base64url.`, { keyid: aid });
  }
  // No length check after this, and the asymmetry with the Python port is deliberate: there,
  // base64's alphabet includes "=", so a 44-character AID can be padded and still decode short.
  // Here the character class excludes "=", so 44 valid characters always decode to 33 bytes and a
  // length check would be unreachable code claiming to guard something.
  const decoded = fromBase64Url('A' + aid.slice(1));
  // The second character's top two bits land in the pad byte the code replaced, so a non-zero pad
  // would give one key two spellings. Only the canonical one, the one toAid produces, is the AID
  // (bakobo/fiki#4).
  if (decoded[0] !== 0) {
    throw new MalformedKey(`The AID ${quoted(aid)} is not the canonical spelling of its key.`, { keyid: aid });
  }
  return checkKey(decoded.slice(1), aid);
}

// keripy's PreDex, the prefix derivation codes an AID may carry, with the raw size each encodes
// (@37rktct3). fiki reads none of them but B; it needs the table only to say whether a keyid is a
// well-formed AID, which the KERI profile's R1 makes the verifier's job before any key store is asked.
const PREFIX_CODES = new Map(Object.entries({
  B: 32, D: 32, E: 32, F: 32, G: 32, H: 32, I: 32,
  '0D': 64, '0E': 64, '0F': 64, '0G': 64,
  '1AAA': 33, '1AAB': 33, '1AAI': 33, '1AAJ': 33,
  '1AAC': 57, '1AAD': 57,
  '1AAE': 114,
}));

/** The non-transferable codes other than B: secp256k1, Ed448 and secp256r1 keys, whose algorithm
 * the profile does not support. */
export const OTHER_NON_TRANSFERABLE = new Set(['1AAA', '1AAC', '1AAI']);

/** The PreDex code of `keyid` when it is a well-formed AID, else null (@7w7nv94j, @37rktct3).
 *
 * The code is one, two or four characters by its first character, as CESR sizes it; the raw bytes
 * behind it are padded with zero bytes to a multiple of three, base64url-encoded, and the code
 * written over the characters the padding became. Well formed means exactly that spelling: the
 * right length, base64url throughout, and zero pad bits, so that re-encoding gives back the keyid.
 * fiki checks this before any resolver sees a keyid, so a resolver only ever answers about key
 * state.
 */
export function aidCode(keyid) {
  const size = /^[A-Za-z]/.test(keyid) ? 1 : keyid[0] === '0' ? 2 : 4;
  const code = keyid.slice(0, size);
  const length = PREFIX_CODES.get(code);
  if (length === undefined) return null;
  const pad = (3 - (length % 3)) % 3;
  if (keyid.length !== ((pad + length) * 4) / 3 + (size - pad)) return null;
  const body = keyid.slice(size);
  // The character class excludes "=", so the body always decodes to pad + length bytes.
  if (!/^[A-Za-z0-9\-_]*$/.test(body)) return null;
  const decoded = fromBase64Url('A'.repeat(pad) + body);
  const spelled = toBase64Url(new Uint8Array([...new Uint8Array(pad), ...decoded.slice(pad)])).slice(pad);
  return code + spelled === keyid ? code : null;
}

/** True when `keyid` is a well-formed AID under the KERI vectors' keys_rule. */
export function wellFormedAid(keyid) {
  return aidCode(keyid) !== null;
}

/** The key a well-formed B keyid carries, read as an AID's key: in the prime-order subgroup. */
export function aidKey(keyid) {
  return checkKey(fromBase64Url('A' + keyid.slice(1)).slice(1), keyid, { subgroup: true });
}

/** An Ed25519 key pair whose public half is rendered as a non-transferable AID. */
export class Key {
  constructor(privateKey, publicRaw, seedBytes) {
    this._privateKey = privateKey;
    this._publicRaw = publicRaw;
    this._seed = seedBytes;
  }

  /** Create a key from fresh randomness. Non-extractable unless asked otherwise. */
  static async generate({ extractable = false } = {}) {
    const pair = await crypto.subtle.generateKey(ALGORITHM, extractable, ['sign', 'verify']);
    const publicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    let seedBytes = null;
    if (extractable) {
      const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
      seedBytes = pkcs8.slice(PKCS8_PREFIX.length);
    }
    return new Key(pair.privateKey, publicRaw, seedBytes);
  }

  /** Recreate a key from its 32-byte Ed25519 seed. */
  static async fromSeed(seed, { extractable = false } = {}) {
    if (!(seed instanceof Uint8Array) || seed.length !== RAW_LEN) {
      throw new MalformedKey(
        `An Ed25519 seed is ${RAW_LEN} bytes; this one is ${seed?.length ?? 0}.`,
        { keyid: '' },
      );
    }
    const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + RAW_LEN);
    pkcs8.set(PKCS8_PREFIX);
    pkcs8.set(seed, PKCS8_PREFIX.length);
    // WebCrypto offers no way to derive a public key from a private one, and the AID *is* the
    // public key, so it has to come out of the key material somehow. A JWK export carries it in
    // "x". That needs an extractable handle, so the seed is imported twice: once extractable and
    // only to read "x", and once with whatever extractability the caller asked for, which is the
    // handle that actually signs. The throwaway is never returned and never stored.
    const forExport = await crypto.subtle.importKey('pkcs8', pkcs8, ALGORITHM, true, ['sign']);
    const { x } = await crypto.subtle.exportKey('jwk', forExport);
    const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, ALGORITHM, extractable, ['sign']);
    return new Key(privateKey, fromBase64Url(x), extractable ? seed : null);
  }

  /** Load an unencrypted OpenSSH Ed25519 private key, as ssh-keygen writes it (@0mvgkwnl).
   *
   * Use a key dedicated to fiki and never loaded into ssh-agent. Signatures do not cross between
   * protocols — every base signRequest and signResponse build begins with a double quote, SSH user
   * authentication signs data beginning with a length-prefixed session identifier (RFC 4252
   * section 7), and SSHSIG signs data beginning "SSHSIG" — but an agent signs whatever bytes it is
   * asked to, so anyone able to use a forwarded agent could sign fiki requests with a login key.
   * The separation is a property of signRequest, not of the key: Key.sign signs any bytes.
   *
   * Non-extractable unless `extractable` is passed, like every other constructor here. Anything
   * but a string is a TypeError; anything malformed is MalformedKey, never quoting the key.
   */
  static async fromOpenssh(text, { extractable = false } = {}) {
    const { seed, raw } = readOpenssh(text);
    const key = await Key.fromSeed(seed, { extractable });
    // The one check readOpenssh cannot make, since deriving a public key takes WebCrypto. It runs
    // last, where fiki-py runs it before the comment and padding checks, so a key wrong in both
    // ways is refused here for its comment or padding and there for its seed: MalformedKey either way.
    if (!equal(key._publicRaw, raw)) throw refusePrivate(DOES_NOT_DERIVE);
    return key;
  }

  /** The non-transferable AID — 44 characters, `B` prefixed, also the verifying key. */
  get aid() {
    return toAid(this._publicRaw);
  }

  /** The raw verifying key, base64url and unpadded — the RFC 8037 JWK "x" form (@7xrx5evg). */
  get keyid() {
    return toBase64Url(this._publicRaw);
  }

  /** The 32-byte seed, for a caller that has to persist the key somewhere. */
  get seed() {
    if (this._seed === null) {
      throw new MalformedKey(
        'This key is non-extractable, so its seed cannot be read. Create it with ' +
          'generate({extractable: true}) if the identity has to outlive this browser profile.',
        { keyid: this.aid },
      );
    }
    return this._seed;
  }

  /** Sign bytes, returning the raw 64-byte Ed25519 signature. */
  async sign(data) {
    return new Uint8Array(await crypto.subtle.sign(ALGORITHM, this._privateKey, data));
  }
}

/** Verify a raw signature against an AID's recovered key. */
export async function verifySignature(aid, signature, data) {
  return verifyWithRaw(verifyingKey(aid), signature, data);
}

/** Verify a raw signature against a raw 32-byte Ed25519 public key. */
export async function verifyWithRaw(raw, signature, data) {
  const key = await crypto.subtle.importKey('raw', raw, ALGORITHM, false, ['verify']);
  return crypto.subtle.verify(ALGORITHM, key, signature, data);
}

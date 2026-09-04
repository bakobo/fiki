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

import { fromBase64Url, toBase64Url } from './bytes.js';
import { MalformedKey } from './errors.js';

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

/** Recover the raw 32-byte Ed25519 public key from a non-transferable AID. */
export function verifyingKey(aid) {
  if (typeof aid !== 'string' || aid.length !== QB64_LEN || !aid.startsWith(CODE)) {
    throw new MalformedKey(
      `A non-transferable AID is ${QB64_LEN} characters beginning with "${CODE}"; this one is ` +
        `${typeof aid === 'string' ? aid.length : 0} characters and begins with "${String(aid).slice(0, 1)}".`,
      { keyid: aid },
    );
  }
  // Strict rather than lenient: "=" is inside base64's alphabet, so a 44-character string of the
  // right shape can still decode short, and a decoder is exactly the place a quiet shortfall
  // turns into somebody else's exception.
  if (!/^[A-Za-z0-9\-_]{44}$/.test(aid)) {
    throw new MalformedKey(`The AID "${aid}" is not valid base64url.`, { keyid: aid });
  }
  // No length check after this, and the asymmetry with the Python port is deliberate: there,
  // base64's alphabet includes "=", so a 44-character AID can be padded and still decode short.
  // Here the character class excludes "=", so 44 valid characters always decode to 33 bytes and a
  // length check would be unreachable code claiming to guard something.
  return fromBase64Url('A' + aid.slice(1)).slice(1);
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
  const raw = verifyingKey(aid);
  const key = await crypto.subtle.importKey('raw', raw, ALGORITHM, false, ['verify']);
  return crypto.subtle.verify(ALGORITHM, key, signature, data);
}

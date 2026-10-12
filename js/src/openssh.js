// Unencrypted OpenSSH Ed25519 private keys, for `Key.fromOpenssh` (`this.i` @0mvgkwnl).
//
// Kept apart from formats.js, and importing nothing from keys.js, so that keys.js can use it
// without an import cycle. It checks everything an openssh-key-v1 file carries except one thing:
// whether the seed derives the stored public key. That takes WebCrypto, which is async, so
// `Key.fromOpenssh` checks it after this reader returns. A seed always derives a point of prime
// order, so once that check passes the small-order refusal of @37wdchu5 cannot fire.

import { equal, fromBase64, toBase64 } from './bytes.js';
import { MalformedKey } from './errors.js';

/** Checked before anything is decoded (input-handling standard: size, then shape, then meaning). */
export const MAX_PRIVATE_CHARS = 4096;

const RAW_LEN = 32;
const SSH_TYPE = new TextEncoder().encode('ssh-ed25519');
const NONE = new TextEncoder().encode('none');
const B64STD = /^[A-Za-z0-9+/]*={0,2}$/;
const BEGIN = '-----BEGIN OPENSSH PRIVATE KEY-----';
const END = '-----END OPENSSH PRIVATE KEY-----';
const MAGIC = new TextEncoder().encode('openssh-key-v1\0');

/** Padded standard base64, or null unless `text` is the one canonical spelling of its bytes.
 * Also used by formats.js, which reads the same encoding in a public key line. */
export function b64std(text) {
  if (!B64STD.test(text) || text.length % 4) return null;
  const data = fromBase64(text);
  return toBase64(data) === text ? data : null;
}

/** RFC 4251 section 5 wire fields, answering null for any length that overruns what is there. */
class Reader {
  constructor(data) {
    this.data = data;
    this.pos = 0;
  }

  uint32() {
    if (this.data.length - this.pos < 4) return null;
    const d = this.data;
    const p = this.pos;
    this.pos += 4;
    return ((d[p] << 24) | (d[p + 1] << 16) | (d[p + 2] << 8) | d[p + 3]) >>> 0;
  }

  string() {
    const length = this.uint32();
    if (length === null || length > this.data.length - this.pos) return null;
    const value = this.data.subarray(this.pos, this.pos + length);
    this.pos += length;
    return value;
  }

  rest() {
    return this.data.subarray(this.pos);
  }
}

const same = (a, b) => a !== null && equal(a, b);

/** The 32 raw bytes of an ssh-ed25519 public blob with nothing after them, or null.
 * Also used by formats.js, which reads the same encoding in a public key line. */
export function sshPublicBlob(blob) {
  const reader = new Reader(blob);
  if (!same(reader.string(), SSH_TYPE)) return null;
  const raw = reader.string();
  return raw !== null && raw.length === RAW_LEN && reader.rest().length === 0 ? raw : null;
}

/** A refusal whose keyid is empty and whose reason never quotes the input: a private key must
 * not reach a log. */
export const refusePrivate = (reason) =>
  new MalformedKey(`The OpenSSH private key was refused: ${reason}`, { keyid: '' });

/** The seed and the stored public key of an unencrypted openssh-key-v1 Ed25519 private key.
 *
 * The text is the armored key as ssh-keygen writes it, LF line endings, with or without the final
 * newline. The key must be the only one in the file, its check integers must agree, its padding
 * must be 1, 2, 3, ..., and its public key must match in both places it is stored. Whether the
 * seed derives that public key is the caller's to check (see the top of this file). Throws
 * MalformedKey otherwise, and the error never carries any part of the key.
 */
export function readOpenssh(text) {
  if (typeof text !== 'string') {
    // A caller's mistake, such as a key read as bytes, and never a FikiError, so that catching
    // fiki's refusals cannot swallow it (@5zrf8gjk).
    throw new TypeError(`An OpenSSH private key is text (a string), not ${describe(text)}.`);
  }
  if (text.length > MAX_PRIVATE_CHARS) throw refusePrivate(`it is over ${MAX_PRIVATE_CHARS} characters.`);
  const lines = (text.endsWith('\n') ? text.slice(0, -1) : text).split('\n');
  if (lines.length < 3 || lines[0] !== BEGIN || lines[lines.length - 1] !== END) {
    throw refusePrivate(`it is not one "${BEGIN}" block with LF line endings and nothing around it.`);
  }
  const body = lines.slice(1, -1);
  if (body.some((line) => !line || !B64STD.test(line))) throw refusePrivate('its body is not lines of standard base64.');
  const blob = b64std(body.join(''));
  if (blob === null) throw refusePrivate('its body is not canonical standard base64.');
  if (blob.length < MAGIC.length || !equal(blob.subarray(0, MAGIC.length), MAGIC)) {
    throw refusePrivate('it is not in the openssh-key-v1 format.');
  }
  const reader = new Reader(blob.subarray(MAGIC.length));
  const cipher = reader.string();
  const kdf = reader.string();
  const kdfoptions = reader.string();
  if (cipher !== null && !equal(cipher, NONE)) {
    throw refusePrivate(
      'it is encrypted under a passphrase, and fiki reads only unencrypted keys. Keep a dedicated ' +
        'key for fiki rather than removing the passphrase from one used elsewhere.',
    );
  }
  if (cipher === null || !same(kdf, NONE) || kdfoptions === null || kdfoptions.length !== 0 || reader.uint32() !== 1) {
    throw refusePrivate('its header is not that of exactly one unencrypted key.');
  }
  const publicBlob = reader.string();
  const raw = publicBlob === null ? null : sshPublicBlob(publicBlob);
  const privateSection = reader.string();
  if (raw === null || privateSection === null || reader.rest().length !== 0) {
    throw refusePrivate('it is not exactly one ssh-ed25519 key with nothing after it.');
  }
  return { seed: readPrivateSection(privateSection, raw), raw };
}

/** The seed from the private section, after every consistency check it carries but derivation. */
function readPrivateSection(section, raw) {
  const reader = new Reader(section);
  const check = reader.uint32();
  if (section.length % 8 || check === null || check !== reader.uint32()) {
    throw refusePrivate('its private section is misaligned or its check integers differ.');
  }
  const ktype = reader.string();
  const inner = reader.string();
  const secret = reader.string();
  const comment = reader.string();
  if (!same(ktype, SSH_TYPE) || !same(inner, raw) || secret === null || secret.length !== 2 * RAW_LEN) {
    throw refusePrivate('its private section does not hold the key its public section names.');
  }
  if (!equal(secret.subarray(RAW_LEN), raw)) throw refusePrivate(DOES_NOT_DERIVE);
  const padding = reader.rest();
  if (comment === null || comment.some((b) => b < 0x20 || b > 0x7e)) {
    throw refusePrivate('its comment is not printable ASCII.');
  }
  if (padding.length >= 8 || padding.some((b, i) => b !== i + 1)) {
    throw refusePrivate('its padding is not 1, 2, 3, ... to the next eight-byte boundary.');
  }
  return secret.slice(0, RAW_LEN);
}

/** The reason for a key whose seed and stored public key disagree, wherever that is found. */
export const DOES_NOT_DERIVE = 'its seed does not derive the public key it is stored with.';

/** A value's kind, for a caller error, without its contents: the value may be a private key. */
export function describe(value) {
  if (value === null) return 'null';
  if (typeof value !== 'object') return typeof value;
  return value.constructor?.name ?? 'an object';
}

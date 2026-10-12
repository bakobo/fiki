// Unencrypted OpenSSH Ed25519 private keys, for `Key.fromOpenssh` (`this.i` @0mvgkwnl).
//
// Kept apart from formats.js, and importing nothing from keys.js, so that keys.js can use it
// without an import cycle. It checks everything an openssh-key-v1 file carries except one thing:
// whether the seed derives the stored public key. That takes WebCrypto, which is async, so
// `Key.fromOpenssh` checks it after this reader returns. A seed always derives a point of prime
// order, so once that check passes the small-order refusal of @37wdchu5 cannot fire.

import { equal, fromBase64, toBase64 } from './bytes.js';

const RAW_LEN = 32;
const SSH_TYPE = new TextEncoder().encode('ssh-ed25519');
const B64STD = /^[A-Za-z0-9+/]*={0,2}$/;

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

/** A value's kind, for a caller error, without its contents: the value may be a private key. */
export function describe(value) {
  if (value === null) return 'null';
  if (typeof value !== 'object') return typeof value;
  return value.constructor?.name ?? 'an object';
}

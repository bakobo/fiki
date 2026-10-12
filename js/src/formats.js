// Other spellings of an Ed25519 public key, read at the edge of the API (`this.i` @0mvgkwnl).
//
// `aidFrom` turns a public key spelled as an AID, as raw base64url (the wire keyid of @7xrx5evg,
// also a JWK's "x"), as a base58btc did:key, as a did:peer with numalgo 0, or as an OpenSSH public
// line into the canonical AID. The OpenSSH private-key reader is openssh.js.
//
// Nothing here touches a request. A verifier calls `aidFrom` when it loads its registrations, so a
// bad one fails at configuration time rather than on a live request, and `expectedAid` stays a
// single spelling. Every spelling has exactly one accepted form: each decoder below re-encodes
// what it decoded, or is a bijection by construction, and refuses a mismatch, so no key has two
// spellings that both pass. Every decoded key then goes through `checkKey`, so no spelling is a way
// around the small-order refusal (@37wdchu5). Synchronous, unlike the Key constructors, because
// nothing here needs WebCrypto.

import { fromBase64Url, toBase64Url } from './bytes.js';
import { MalformedKey } from './errors.js';
import { checkKey, toAid, wellFormedAid } from './keys.js';
import { b64std, describe, sshPublicBlob } from './openssh.js';

/** Checked before anything is decoded, so nothing below ever sees more than this. An OpenSSH
 * public line's comment is the only part of any spelling that varies much, and 1024 characters
 * leaves it ample room. Counted in UTF-16 code units, which is at least the count of code points
 * fiki-py takes; no spelling fiki reads holds a character outside ASCII, so the two can disagree
 * only on text both refuse. */
export const MAX_PUBLIC_CHARS = 1024;

const RAW_LEN = 32;
const AID_LEN = 44;
const RAW_B64URL_LEN = 43;
const ED25519_PUB = [0xed, 0x01]; // multicodec ed25519-pub, 0xed as an unsigned varint
// A base58btc value over 34 bytes is at most 47 characters after the "z"; anything longer cannot be
// an Ed25519 did:key, and refusing it first keeps base58's big-integer arithmetic to a fixed size.
const MAX_MULTIBASE = 48;

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B64URL = /^[A-Za-z0-9_-]*$/;
// "ssh-ed25519", one space, the blob, and optionally one space and a printable-ASCII comment that
// neither begins nor ends with a space, so that no whitespace around any field is ever ignored.
// No m flag, so $ is the end of the text and not the end of a line.
const SSH_LINE = /^ssh-ed25519 ([A-Za-z0-9+/=]+)(?: ([\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?))?$/;

/** Unpadded base64url, or null unless `text` is the one canonical spelling of its bytes. */
function b64url(text) {
  if (!B64URL.test(text) || text.length % 4 === 1) return null;
  const data = fromBase64Url(text);
  return toBase64Url(data) === text ? data : null;
}

/** base58btc, or null. Leading "1"s are zero bytes and the rest is the minimal big-endian bytes of
 * the number, so decoding is a bijection: what it returns re-encodes to `text` exactly, and a
 * leading "1" cannot add a zero byte to some other spelling's key. */
function b58(text) {
  if (!text) return null;
  let number = 0n;
  for (const char of text) {
    const digit = B58.indexOf(char);
    if (digit < 0) return null;
    number = number * 58n + BigInt(digit);
  }
  const zeros = text.length - text.replace(/^1+/, '').length;
  const bytes = [];
  for (; number > 0n; number >>= 8n) bytes.unshift(Number(number & 0xffn));
  return Uint8Array.from([...new Array(zeros).fill(0), ...bytes]);
}

/** The raw key under a did:key multibase value, which is base58btc ("z") only.
 *
 * The did:key ABNF also admits base64url ("u"), but the spec's resolution algorithm requires the
 * value to "begin with the letter `z`" or raise invalidDid, and the peer DID ABNF has
 * transform = "z". Reading "u" too would give every key two DIDs.
 */
function multibaseEd25519(value) {
  if (value.length > MAX_MULTIBASE || value[0] !== 'z') return null;
  const decoded = b58(value.slice(1));
  if (decoded === null || decoded.length !== ED25519_PUB.length + RAW_LEN) return null;
  return decoded[0] === ED25519_PUB[0] && decoded[1] === ED25519_PUB[1] ? decoded.slice(2) : null;
}

/** The 32 bytes under a canonically spelled 44-character AID, whatever its code. */
const aidBody = (text) => fromBase64Url('A' + text.slice(1)).slice(1);

/** The raw key `text` spells, by its shape, or null for a shape fiki does not read. */
function rawOf(text) {
  if (text.length === AID_LEN && text[0] === 'B') return wellFormedAid(text) ? aidBody(text) : null;
  if (text.length === RAW_B64URL_LEN) return b64url(text);
  if (text.startsWith('did:key:')) return multibaseEd25519(text.slice('did:key:'.length));
  if (text.startsWith('did:peer:0')) return multibaseEd25519(text.slice('did:peer:0'.length));
  const line = SSH_LINE.exec(text);
  if (line) {
    const blob = b64std(line[1]);
    return blob === null ? null : sshPublicBlob(blob);
  }
  return null;
}

/** The canonical AID of the Ed25519 public key `text` spells.
 *
 * `text` is an AID, the raw key as 43 characters of unpadded base64url (a JWK's "x"), a did:key, a
 * did:peer with numalgo 0, or an OpenSSH public line — "ssh-ed25519", one space, the blob, and
 * optionally one space and a printable-ASCII comment that neither begins nor ends with a space.
 * Length, not the first character, tells raw from AID: 43 against 44. Nothing around `text` is
 * stripped; that is the caller's, so that one input never has two readings.
 *
 * Throws MalformedKey for anything else, including a transferable or digest AID, whose key is not
 * the identifier's to give. The error never quotes `text` and its keyid is empty, because what is
 * handed here by mistake can be a private key: the .key file instead of the .pub, or a seed, which
 * in base64url is 43 characters like a raw key. Anything but a string is a TypeError.
 */
export function aidFrom(text) {
  if (typeof text !== 'string') {
    // A caller's mistake, and never a FikiError, so that catching fiki's refusals cannot swallow
    // it (@5zrf8gjk). Its kind is named and its contents are not: it may be a key read as bytes.
    throw new TypeError(`A public key is text (a string), not ${describe(text)}.`);
  }
  if (text.length > MAX_PUBLIC_CHARS) {
    throw new MalformedKey(
      `A public key is at most ${MAX_PUBLIC_CHARS} characters in any spelling fiki reads; this one is ` +
        `${text.length}.`,
      { keyid: '' },
    );
  }
  // Shape before meaning: only a canonically spelled D or E AID is told what it is.
  if ((text[0] === 'D' || text[0] === 'E') && wellFormedAid(text)) {
    throw new MalformedKey(
      'The text is a transferable or digest AID, whose current key is not recoverable from the ' +
        'identifier; resolve it to a key first.',
      { keyid: '' },
    );
  }
  const raw = rawOf(text);
  if (raw === null) {
    throw new MalformedKey(
      `The text, ${text.length} characters, is not an Ed25519 public key in any spelling fiki reads: ` +
        'an AID, raw base64url, a base58btc did:key, a did:peer:0, or an ssh-ed25519 line.',
      { keyid: '' },
    );
  }
  return toAid(checkKey(raw, ''));
}

// Base64 without Buffer (`this.i` @2q9gv70t).
//
// `Buffer` is Node's, and reaching for it is the easiest way to write a "browser" library that
// only runs on a server. `btoa`/`atob` are in every browser and in Node 20+, so these four
// functions are the whole of fiki's binary-to-text needs and the port stays honest about its
// target.

const toBinaryString = (bytes) => {
  let out = '';
  // One character at a time rather than String.fromCharCode(...bytes): spreading a large array
  // into a call blows the argument limit, and a signature base's digest is small but a body is
  // not, so the shape that works for both is the one to use everywhere.
  for (const byte of bytes) out += String.fromCharCode(byte);
  return out;
};

const fromBinaryString = (text) => Uint8Array.from(text, (char) => char.charCodeAt(0));

export const toBase64 = (bytes) => btoa(toBinaryString(bytes));

export const fromBase64 = (text) => fromBinaryString(atob(text));

export const toBase64Url = (bytes) => toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export const fromBase64Url = (text) => {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  return fromBase64(padded + '='.repeat((4 - (padded.length % 4)) % 4));
};

export const utf8 = (text) => new TextEncoder().encode(text);

export const equal = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);

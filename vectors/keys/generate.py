#!/usr/bin/env python3
"""Regenerate the key-spelling vectors (``this.i`` @0mvgkwnl).

Run from the repository root: ``uv run --project py --with base58 python vectors/keys/generate.py``.

A contract of its own, with its own monotonic ``key_vectors_format``, so that a port can ship the
key converters without moving the shared ``vectors_format``. Every port runs ``keys.json``.

fiki's own converters are deliberately NOT imported here: a vector produced by the code it tests
pins whatever that code does, bugs included. Each expected value comes from somewhere else.

* An AID comes from ``fiki.to_aid`` over raw bytes, which predates this work and is corroborated
  by keripy (``vectors/generate.py``).
* base58btc comes from the independent ``base58`` package, and the did:key spec's own example
  DIDs are carried verbatim, decoded by that package rather than by fiki.
* The did:peer numalgo 0 example is the peer DID spec's own, which states it equivalent to the
  did:key with the same multibase value (spec/core.md, "Method 0").
* An OpenSSH public line comes from ``cryptography``'s OpenSSH serializer, and an OpenSSH private
  key either from ``ssh-keygen`` itself (the files in ``openssh/``) or from the small writer below,
  whose well-formed output must load in ``cryptography`` and be read back by ``ssh-keygen -y``
  before anything is written.

Every malformed private key records whether ``ssh-keygen`` also refuses it, so a reader can see
where fiki is stricter than OpenSSH and decide whether that is wanted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "py" / "src"))

from fiki import to_aid  # noqa: E402

# Monotonic, for the reason vectors/generate.py gives: even adding a case is breaking.
KEY_VECTORS_FORMAT = 1

# The bounds @0mvgkwnl sets, checked before anything is decoded.
MAX_PUBLIC_CHARS = 1024
MAX_PRIVATE_CHARS = 4096

SEED_A = bytes(range(32))
SEED_B = bytes(range(1, 33))
# RFC 9421 Appendix B.1.4's Ed25519 key, the JWK "d" value (as in vectors/generate.py).
RFC_SEED = base64.urlsafe_b64decode("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU=")
MESSAGE = b"fiki"

# The identity point, small order, and y = p, which is not a canonical encoding (@37wdchu5).
IDENTITY = b"\x01" + b"\x00" * 31
Y_IS_P = b"\xed" + b"\xff" * 30 + b"\x7f"

ED25519_PUB = b"\xed\x01"  # the multicodec ed25519-pub header, varint 0xed
X25519_PUB = b"\xec\x01"
SECP256K1_PUB = b"\xe7\x01"
CHECKINT = 0x66696B69  # "fiki", fixed so regeneration is byte-stable


def raw_of(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def z(data: bytes) -> str:
    return "z" + base58.b58encode(data).decode("ascii")


def u(data: bytes) -> str:
    return "u" + b64url(data)


def string(data: bytes) -> bytes:
    """An SSH wire-format string (RFC 4251 section 5): a uint32 length, then the bytes."""
    return struct.pack(">I", len(data)) + data


def ssh_blob(raw: bytes, ktype: bytes = b"ssh-ed25519") -> bytes:
    return string(ktype) + string(raw)


def ssh_line(raw: bytes, comment: str | None = None) -> str:
    """The OpenSSH public line, from cryptography's serializer rather than from ssh_blob."""
    line = (
        Ed25519PublicKey.from_public_bytes(raw)
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode("ascii")
    )
    assert line == "ssh-ed25519 " + b64(ssh_blob(raw)), "cryptography and ssh_blob disagree"
    return line if comment is None else f"{line} {comment}"


def flip_spare_bits(text: str, alphabet: str) -> str:
    """The same text with the unused low bits of its last character set, a second spelling."""
    last = alphabet.index(text[-1])
    return text[:-1] + alphabet[last | 1]


B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
B64STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


# --- public spellings ---


def public_accepts() -> list[dict]:
    cases = []

    def add(case_id, text, raw, source):
        cases.append({"id": case_id, "input": text, "aid": to_aid(raw), "source": source})

    a, b, rfc = raw_of(SEED_A), raw_of(SEED_B), raw_of(RFC_SEED)
    add("aid", to_aid(a), a, "the AID itself, unchanged")
    add("raw-b64url", b64url(a), a, "the wire keyid of @7xrx5evg, also a JWK's x member")
    add("raw-b64url-rfc", b64url(rfc), rfc, "RFC 9421 B.1.4's key as its JWK x member")
    # Length, not the first character, tells raw from AID: 43 against 44. A raw key whose
    # base64url happens to begin with an AID code is still a raw key.
    for code in "BDE":
        seed = next(
            seed for seed in (hashlib.sha256(b"%d" % n).digest() for n in range(100_000))
            if b64url(raw_of(seed)).startswith(code)
        )
        add(f"raw-b64url-begins-{code}", b64url(raw_of(seed)), raw_of(seed),
            f"a raw key whose first character is {code}, read by length rather than by prefix")
    add("did-key-z", "did:key:" + z(ED25519_PUB + a), a, "base58btc via the base58 package")
    add("did-key-z-b", "did:key:" + z(ED25519_PUB + b), b, "base58btc via the base58 package")
    add("did-peer-0-z", "did:peer:0" + z(ED25519_PUB + a), a, "peer DID numalgo 0")
    # The specs' own examples, decoded by the base58 package and checked for the header.
    for case_id, did, source in (
        ("did-key-spec-example-1", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
         "w3c-ccg/did-key-spec index.html, the simple Ed25519 example"),
        ("did-key-spec-example-2", "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
         "w3c-ccg/did-key-spec index.html"),
        ("did-peer-spec-example", "did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
         "peer-did-method-spec spec/core.md, Method 0"),
        ("did-key-peer-equivalent", "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
         "peer-did-method-spec spec/core.md, the did:key it calls equivalent"),
    ):
        multibase = did.split(":")[-1].removeprefix("0")  # did:peer:0 puts numalgo first
        assert multibase[0] == "z", case_id
        decoded = base58.b58decode(multibase[1:])
        assert decoded[:2] == ED25519_PUB and len(decoded) == 34, case_id
        add(case_id, did, decoded[2:], source)
    add("ssh", ssh_line(a), a, "cryptography's OpenSSH serializer")
    add("ssh-comment", ssh_line(a, "alice@example.com"), a, "with a comment")
    add("ssh-comment-spaces", ssh_line(a, "fiki test key, never use"), a, "a comment may hold spaces")
    at_bound = ssh_line(a, "x" * (MAX_PUBLIC_CHARS - len(ssh_line(a)) - 1))
    assert len(at_bound) == MAX_PUBLIC_CHARS
    add("ssh-at-bound", at_bound, a, "exactly the 1024-character bound, which is inclusive")
    pub = (HERE / "openssh" / "ed25519.pub").read_text("ascii").rstrip("\n")
    fixture = serialization.load_ssh_public_key(pub.encode("ascii")).public_bytes_raw()
    add("ssh-keygen-pub", pub, fixture, "openssh/ed25519.pub as ssh-keygen wrote it, newline removed")
    return cases


def public_refusals() -> list[dict]:
    cases = []

    def refuse(case_id, text, why):
        cases.append({"id": case_id, "input": text, "error": "MalformedKey", "why": why})

    a = raw_of(SEED_A)
    aid = to_aid(a)
    refuse("empty", "", "nothing to read")
    refuse("too-long", "did:key:z" + "1" * (MAX_PUBLIC_CHARS - 8), "over the 1024-character bound")
    over = ssh_line(a, "x" * (MAX_PUBLIC_CHARS - len(ssh_line(a))))
    assert len(over) == MAX_PUBLIC_CHARS + 1
    refuse("ssh-over-bound", over, "one character over the bound, otherwise well formed")
    refuse("whitespace-leading", " " + aid, "surrounding whitespace is the caller's to strip")
    refuse("whitespace-trailing", aid + "\n", "a line terminator is the caller's to strip")
    refuse("unknown-shape", "hello", "no spelling fiki reads")
    # The AID and the raw key.
    assert B64URL.index(aid[1]) & 0x20 == 0, "the misspelling below must change the text"
    refuse("aid-misspelled", "B" + B64URL[B64URL.index(aid[1]) | 0x20] + aid[2:],
           "the pad bits under the code are non-zero, a second spelling of a key")
    refuse("aid-transferable", "D" + aid[1:], "a D prefix embeds an inception key that may have rotated away")
    refuse("aid-digest", "E" + aid[1:], "an E prefix is a digest, not a key")
    refuse("aid-small-order", to_aid(IDENTITY), "the identity point, under which any signature verifies")
    refuse("raw-padded", b64url(a) + "=", "base64url padding is not part of the raw form")
    refuse("raw-std-alphabet", base64.b64encode(b"\xfb" * 32).decode("ascii").rstrip("="),
           "the standard alphabet's + and / are not base64url")
    refuse("raw-spare-bits", flip_spare_bits(b64url(a), B64URL), "the two unused bits are non-zero")
    refuse("raw-short", b64url(a)[:42], "42 characters do not hold 32 bytes")
    refuse("raw-small-order", b64url(IDENTITY), "the identity point")
    refuse("raw-not-on-curve", b64url(Y_IS_P), "y = p is not a canonical encoding")
    # Lengths are counted in code points. A UTF-16 port that counts code units sees these two as
    # 44 and 45 long, and must still refuse them rather than read one as an AID.
    refuse("raw-astral-at-43", b64url(a)[:42] + "\U0001F600", "an emoji where a raw key's last character goes")
    refuse("aid-astral-at-44", aid[:43] + "\U0001F600", "an emoji where an AID's last character goes")
    refuse("raw-fullwidth", b64url(a)[:42] + "Ａ", "a fullwidth letter is not base64url")
    # did:key and did:peer:0.
    good = z(ED25519_PUB + a)
    refuse("did-key-uppercase-scheme", "DID:KEY:" + good, "DID scheme and method are lowercase")
    refuse("did-key-no-multibase", "did:key:" + good[1:], "no multibase prefix")
    refuse("did-key-base16", "did:key:f" + (ED25519_PUB + a).hex(), "base16 is not in the did:key ABNF")
    refuse("did-key-bad-base58", "did:key:" + good[:-1] + "0", "0 is not in the base58btc alphabet")
    refuse("did-key-base58-leading-one", "did:key:z1" + good[1:],
           "a leading 1 adds a zero byte, a second spelling of the same key")
    refuse("did-key-x25519", "did:key:" + z(X25519_PUB + a), "an X25519 key cannot verify a signature")
    refuse("did-key-secp256k1", "did:key:" + z(SECP256K1_PUB + b"\x02" + a), "not an Ed25519 key")
    refuse("did-key-varint-non-minimal", "did:key:" + z(b"\xed\x81\x00" + a),
           "0xed in a non-minimal varint, a second spelling of the header")
    refuse("did-key-short", "did:key:" + z(ED25519_PUB + a[:31]), "31 bytes of key")
    refuse("did-key-long", "did:key:" + z(ED25519_PUB + a + b"\x00"), "33 bytes of key")
    refuse("did-key-fragment", "did:key:" + good + "#" + good, "a DID URL, not a DID")
    refuse("did-key-query", "did:key:" + good + "?x=1", "a DID URL, not a DID")
    # The did:key ABNF admits a base64url ("u") value, but the spec's resolution algorithm says the
    # value "MUST be a string and begin with the letter `z`" or invalidDid "MUST be raised", and
    # the peer DID ABNF has transform = "z". Reading "u" as well would give every key two DIDs.
    refuse("did-key-u", "did:key:" + u(ED25519_PUB + a), "did:key resolution requires z")
    refuse("did-peer-0-u", "did:peer:0" + u(ED25519_PUB + a), "peer DID transform is z only")
    refuse("did-key-u-45", "did:key:u" + b64url(ED25519_PUB + a)[:45], "a length no base64url has")
    refuse("did-key-header-ed02", "did:key:" + z(b"\xed\x02" + a), "the second header byte is wrong")
    refuse("did-peer-1-key", "did:peer:1" + good, "numalgo 1 is a document hash, not a key")
    refuse("did-key-u-padded", "did:key:" + u(ED25519_PUB + a) + "==", "base64url padding")
    refuse("did-key-u-spare-bits", "did:key:u" + flip_spare_bits(b64url(ED25519_PUB + a), B64URL),
           "the unused bits are non-zero")
    refuse("did-key-small-order", "did:key:" + z(ED25519_PUB + IDENTITY), "the identity point")
    refuse("did-key-not-on-curve", "did:key:" + z(ED25519_PUB + Y_IS_P), "y = p")
    refuse("did-key-empty", "did:key:", "no key")
    refuse("did-peer-2", "did:peer:2.Vz" + good[1:], "numalgo 2 carries a document, not one key")
    refuse("did-peer-no-numalgo", "did:peer:" + good, "numalgo is required")
    refuse("did-peer-0-x25519", "did:peer:0" + z(X25519_PUB + a), "not an Ed25519 key")
    # OpenSSH public lines.
    line = ssh_line(a)
    blob = b64(ssh_blob(a))
    refuse("ssh-rsa", (HERE / "openssh" / "rsa.pub").read_text("ascii").rstrip("\n"), "an RSA key")
    refuse("ssh-ecdsa", (HERE / "openssh" / "ecdsa.pub").read_text("ascii").rstrip("\n"), "an ECDSA key")
    refuse("ssh-sk", "sk-ssh-ed25519@openssh.com " + b64(
        string(b"sk-ssh-ed25519@openssh.com") + string(a) + string(b"ssh:")),
        "a security-key signature carries flags and a counter, not plain Ed25519")
    refuse("ssh-type-mismatch", "ssh-ed25519 " + b64(ssh_blob(a, b"ssh-rsa")),
           "the blob names another key type than the line does")
    refuse("ssh-trailing-bytes", "ssh-ed25519 " + b64(ssh_blob(a) + b"\x00"), "bytes after the key")
    refuse("ssh-short-key", "ssh-ed25519 " + b64(ssh_blob(a[:31])), "31 bytes of key")
    refuse("ssh-length-overrun", "ssh-ed25519 " + b64(string(b"ssh-ed25519") + struct.pack(">I", 64) + a),
           "a length longer than what follows")
    refuse("ssh-two-spaces", "ssh-ed25519  " + blob, "one space separates the fields")
    refuse("ssh-tab", "ssh-ed25519\t" + blob, "one space separates the fields")
    refuse("ssh-crlf", line + "\r\n", "a line terminator is the caller's to strip")
    refuse("ssh-options", "restrict " + line, "an authorized_keys options prefix")
    refuse("ssh-empty-comment", line + " ", "a separator promises a comment")
    refuse("ssh-comment-control", line + " a\x00b", "a control character in the comment")
    refuse("ssh-comment-newline", line + " a\nssh-ed25519 " + b64(ssh_blob(raw_of(SEED_B))),
           "a second line smuggled in the comment")
    refuse("ssh-comment-del", line + " a\x7fb", "DEL is a control character")
    refuse("ssh-comment-leading-space", line + "  x", "the comment may not begin with a space")
    refuse("ssh-comment-trailing-space", line + " x ", "the comment may not end with a space")
    refuse("ssh-two-trailing-spaces", line + "  ", "surrounding whitespace is the caller's to strip")
    refuse("ssh-blob-then-padding-and-more", line[:len("ssh-ed25519 ") + len(blob)] + "=AAAA",
           "base64 that continues after padding")
    refuse("ssh-comment-non-ascii", line + " café", "the comment is printable ASCII only")
    # An ssh-ed25519 blob is 51 bytes, a multiple of three, so its base64 has neither padding
    # nor spare bits to get wrong; padding appended to it is the only malformation of that kind.
    assert len(ssh_blob(a)) % 3 == 0
    refuse("ssh-blob-padded", line + "=", "padding after a blob that needs none")
    refuse("ssh-blob-url-alphabet", "ssh-ed25519 " + base64.urlsafe_b64encode(ssh_blob(b"\xfb" * 32)).decode(),
           "the blob is standard base64, not base64url")
    refuse("ssh-small-order", "ssh-ed25519 " + b64(ssh_blob(IDENTITY)), "the identity point")
    refuse("ssh-uppercase-type", "SSH-ED25519 " + blob, "key types are case-sensitive")
    # A private key handed over by mistake: refused, and (each port's own tests check) never
    # echoed into the error.
    refuse("openssh-private-key", (HERE / "openssh" / "ed25519.key").read_text("ascii"),
           "a private key, the .key file given where the .pub was meant")
    refuse("pkcs8-private-key", Ed25519PrivateKey.from_private_bytes(SEED_A).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii"), "a PKCS #8 private key")
    return cases


# --- OpenSSH private keys ---


def openssh_key(
    seed: bytes,
    *,
    comment: bytes = b"",
    cipher: bytes = b"none",
    kdf: bytes = b"none",
    kdfoptions: bytes = b"",
    nkeys: int = 1,
    checkints: tuple[int, int] = (CHECKINT, CHECKINT),
    ktype: bytes = b"ssh-ed25519",
    public_raw: bytes | None = None,
    inner_public_raw: bytes | None = None,
    private_tail: bytes | None = None,
    padding: bytes | None = None,
    extra_private: bytes = b"",
    trailing: bytes = b"",
    magic: bytes = b"openssh-key-v1\x00",
) -> bytes:
    """openssh-key-v1 (OpenSSH PROTOCOL.key), with every field overridable for a refusal case."""
    raw = raw_of(seed)
    public_raw = raw if public_raw is None else public_raw
    inner_public_raw = raw if inner_public_raw is None else inner_public_raw
    private_tail = raw if private_tail is None else private_tail
    private = (
        struct.pack(">II", *checkints)
        + string(ktype)
        + string(inner_public_raw)
        + string(seed + private_tail)
        + string(comment)
        + extra_private
    )
    if padding is None:
        padding = bytes(range(1, 1 + (-len(private)) % 8))
    private += padding
    return (
        magic
        + string(cipher)
        + string(kdf)
        + string(kdfoptions)
        + struct.pack(">I", nkeys)
        + string(ssh_blob(public_raw, ktype))
        + string(private)
        + trailing
    )


def armor(blob: bytes, *, width: int = 70, eol: str = "\n", final_eol: bool = True) -> str:
    body = b64(blob)
    lines = [body[i:i + width] for i in range(0, len(body), width)]
    text = eol.join(["-----BEGIN OPENSSH PRIVATE KEY-----", *lines, "-----END OPENSSH PRIVATE KEY-----"])
    return text + eol if final_eol else text


def ssh_keygen_reads(text: str) -> bool:
    """Whether ``ssh-keygen -y`` derives a public key from ``text``, with no passphrase."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "key"
        path.write_text(text, "ascii", newline="")
        os.chmod(path, 0o600)
        done = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", str(path)],
            capture_output=True, text=True, stdin=subprocess.DEVNULL, check=False,
        )
        return done.returncode == 0


def signature(seed: bytes) -> str:
    return b64url(Ed25519PrivateKey.from_private_bytes(seed).sign(MESSAGE))


def private_accepts() -> list[dict]:
    cases = []

    def add(case_id, text, seed, source, *, lenient=False):
        loaded = serialization.load_ssh_private_key(text.encode("ascii"), password=None)
        assert loaded.private_bytes_raw() == seed, case_id
        # Only a case marked lenient may be one ssh-keygen refuses, so that every place fiki is
        # more permissive than OpenSSH is named in the file rather than discovered.
        assert ssh_keygen_reads(text) != lenient, f"{case_id}: ssh-keygen disagrees unexpectedly"
        cases.append({
            "id": case_id, "input": text, "aid": to_aid(raw_of(seed)),
            "signature": signature(seed), "source": source, "ssh_keygen_refuses": lenient,
        })

    fixture = (HERE / "openssh" / "ed25519.key").read_text("ascii")
    fixture_seed = serialization.load_ssh_private_key(
        fixture.encode("ascii"), password=None
    ).private_bytes_raw()
    add("ssh-keygen", fixture, fixture_seed, "openssh/ed25519.key as ssh-keygen wrote it")
    add("ssh-keygen-no-final-newline", fixture.rstrip("\n"), fixture_seed,
        "no final newline, which OpenSSH 10.2 refuses and fiki accepts, because a secret store or an "
        "environment variable routinely strips it and the shorter text means nothing else", lenient=True)
    add("written", armor(openssh_key(SEED_A, comment=b"fiki")), SEED_A, "this generator's writer")
    add("written-no-comment", armor(openssh_key(SEED_A)), SEED_A, "an empty comment")
    near = next(
        text for text in (armor(openssh_key(SEED_A, comment=b"x" * n)) for n in range(3000, 2000, -1))
        if len(text) <= MAX_PRIVATE_CHARS
    )
    assert len(near) > MAX_PRIVATE_CHARS - 80
    add("written-near-bound", near, SEED_A, "the longest key this writer makes within the bound")
    add("written-long-lines", armor(openssh_key(SEED_B), width=64), SEED_B, "64-character lines")
    add("cryptography", serialization.load_ssh_private_key(
        armor(openssh_key(RFC_SEED)).encode("ascii"), password=None
    ).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    ).decode("ascii"), RFC_SEED, "cryptography's OpenSSH writer, RFC 9421 B.1.4's key")
    return cases


def private_refusals() -> list[dict]:
    cases = []

    def refuse(case_id, text, why):
        cases.append({
            "id": case_id, "input": text, "error": "MalformedKey", "why": why,
            "ssh_keygen_refuses": not ssh_keygen_reads(text),
        })

    good = armor(openssh_key(SEED_A))
    other = raw_of(SEED_B)
    refuse("empty", "", "nothing to read")
    refuse("too-long", armor(openssh_key(SEED_A, comment=b"x" * 3000)), "over the 4096-character bound")
    refuse("encrypted", (HERE / "openssh" / "ed25519-encrypted.key").read_text("ascii"),
           "encrypted under a passphrase, which fiki does not decrypt")
    refuse("rsa", (HERE / "openssh" / "rsa.key").read_text("ascii"), "an RSA key")
    refuse("ecdsa", (HERE / "openssh" / "ecdsa.key").read_text("ascii"), "an ECDSA key")
    pkcs8 = Ed25519PrivateKey.from_private_bytes(SEED_A).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")
    refuse("pkcs8", pkcs8, "a PKCS #8 key, not OpenSSH's format")
    refuse("public-line", ssh_line(raw_of(SEED_A)), "a public key")
    refuse("leading-text", "key:\n" + good, "text before the armor")
    refuse("trailing-text", good + "more\n", "text after the armor")
    refuse("missing-end", good.replace("-----END OPENSSH PRIVATE KEY-----\n", ""), "no closing armor")
    refuse("blank-line", good.replace("\n", "\n\n", 2).replace("\n\n", "\n", 1), "an empty line in the body")
    refuse("space-in-body", good[:60] + " " + good[60:], "a space in the base64 body")
    refuse("bare-cr", good.replace("\n", "\r"), "a line ending that is neither LF nor CRLF")
    refuse("crlf", good.replace("\n", "\r\n"), "CRLF line endings, which ssh-keygen also refuses")
    refuse("mixed-line-endings", good.replace("\n", "\r\n", 1), "LF and CRLF in one key")
    assert "+" in good or "/" in good, "pick a seed whose body exercises the alphabet difference"
    refuse("body-url-alphabet", good.replace("+", "-").replace("/", "_"),
           "base64url characters in a standard base64 body")
    # The private section is padded to eight bytes, so only a comment eight bytes longer moves
    # the blob's length modulo three, and with it whether the base64 needs padding.
    blob = next(b for b in (openssh_key(SEED_A, comment=b"a" * n) for n in range(0, 32, 8)) if len(b) % 3)
    body = b64(blob).rstrip("=")
    assert body != b64(blob), "the body must have padding for its absence to matter"
    refuse("body-unpadded", "-----BEGIN OPENSSH PRIVATE KEY-----\n" + body
           + "\n-----END OPENSSH PRIVATE KEY-----\n", "standard base64 keeps its padding")
    refuse("bad-magic", armor(openssh_key(SEED_A, magic=b"openssh-key-v2\x00")), "an unknown format")
    refuse("cipher", armor(openssh_key(SEED_A, cipher=b"aes256-ctr")), "a cipher with no KDF")
    refuse("kdf", armor(openssh_key(SEED_A, kdf=b"bcrypt")), "a KDF with no cipher")
    refuse("kdfoptions", armor(openssh_key(SEED_A, kdfoptions=b"\x00")), "KDF options under no KDF")
    header = b"openssh-key-v1\x00" + string(b"none") + string(b"none") + string(b"")
    refuse("truncated-header", armor(header), "the key count and everything after it are missing")
    refuse("truncated-public", armor(header + struct.pack(">I", 1) + struct.pack(">I", 51) + ssh_blob(raw_of(SEED_A))[:20]),
           "a public section shorter than its length")
    refuse("empty-private-section", armor(header + struct.pack(">I", 1) + string(ssh_blob(raw_of(SEED_A))) + string(b"")),
           "a private section with nothing in it")
    refuse("two-keys", armor(openssh_key(SEED_A, nkeys=2)), "more than one key")
    refuse("zero-keys", armor(openssh_key(SEED_A, nkeys=0)), "no key")
    refuse("checkint-mismatch", armor(openssh_key(SEED_A, checkints=(1, 2))),
           "the check integers differ, which is how OpenSSH detects a wrong passphrase")
    refuse("padding-wrong", armor(openssh_key(SEED_A, padding=b"\x01\x02\x04")), "padding is 1, 2, 3, ...")
    refuse("padding-block", armor(openssh_key(SEED_A, padding=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b")),
           "padding that leaves the private section misaligned")
    natural = len(openssh_key(SEED_A)) - len(openssh_key(SEED_A, padding=b""))
    refuse("padding-extra-block", armor(openssh_key(SEED_A, padding=bytes(range(1, natural + 9)))),
           "a whole extra block of padding, aligned, which ssh-keygen reads")
    refuse("unaligned", armor(openssh_key(SEED_A, padding=b"\x01\x02")), "the private section is not a multiple of eight")
    refuse("type-mismatch", armor(openssh_key(SEED_A, ktype=b"ssh-rsa")), "not ssh-ed25519")
    refuse("public-mismatch", armor(openssh_key(SEED_A, public_raw=other)),
           "the public section names another key than the private section")
    refuse("inner-public-mismatch", armor(openssh_key(SEED_A, inner_public_raw=other)),
           "the private section's public key is not the seed's")
    refuse("private-tail-mismatch", armor(openssh_key(SEED_A, private_tail=other)),
           "the 64-byte private key's second half is not the seed's public key")
    refuse("all-publics-another-key", armor(openssh_key(SEED_A, public_raw=other, inner_public_raw=other,
                                                       private_tail=other)),
           "every stored public key agrees, and none is the one the seed derives")
    refuse("comment-del", armor(openssh_key(SEED_A, comment=b"a\x7f")), "DEL in the comment")
    refuse("tab-in-body", good.replace("\n", "\n\t", 2).replace("\n\t", "\n", 1), "a tab in the body")
    padded_blob = next(b for b in (openssh_key(SEED_A, comment=b"a" * n) for n in range(0, 32, 8)) if len(b) % 3 == 1)
    padded_body = b64(padded_blob)
    assert padded_body.endswith("==") and B64STD.index(padded_body[-3]) & 1 == 0
    refuse("body-spare-bits", "-----BEGIN OPENSSH PRIVATE KEY-----\n" + flip_spare_bits(padded_body[:-2], B64STD)
           + "==\n-----END OPENSSH PRIVATE KEY-----\n", "the base64 body's unused bits are non-zero")
    refuse("public-small-order", armor(openssh_key(SEED_A, public_raw=IDENTITY, inner_public_raw=IDENTITY,
                                                   private_tail=IDENTITY)),
           "a public key of small order, whatever the seed")
    refuse("trailing-bytes", armor(openssh_key(SEED_A, trailing=b"\x00\x00\x00\x00")), "bytes after the private section")
    refuse("extra-private", armor(openssh_key(SEED_A, extra_private=b"\x00\x00\x00\x00")),
           "a field after the comment that is not padding")
    refuse("comment-control", armor(openssh_key(SEED_A, comment=b"a\nb")), "a control character in the comment")
    return cases


def main() -> None:
    if shutil.which("ssh-keygen") is None:
        sys.exit("ssh-keygen is required: it is the oracle for every private-key case.")
    data = {
        "about": "Key-spelling vectors for fiki (this.i @0mvgkwnl). Every implementation runs these.",
        "key_vectors_format": KEY_VECTORS_FORMAT,
        "generated_by": "vectors/keys/generate.py",
        "max_public_chars": MAX_PUBLIC_CHARS,
        "max_private_chars": MAX_PRIVATE_CHARS,
        "signed_message": MESSAGE.decode("ascii"),
        "public": {"accepts": public_accepts(), "refusals": public_refusals()},
        "private": {"accepts": private_accepts(), "refusals": private_refusals()},
    }
    for section in ("public", "private"):
        ids = [c["id"] for kind in ("accepts", "refusals") for c in data[section][kind]]
        assert len(ids) == len(set(ids)), f"duplicate case id in {section}"
    (HERE / "keys.json").write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

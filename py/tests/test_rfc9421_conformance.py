"""Conformance against RFC 9421's own Appendix B vectors (``this.i`` @5gf6r08f).

This is fiki's first oracle and the first test written, because no Bakobo party authored it. Every
literal below was read from the RFC text verbatim (``https://www.rfc-editor.org/rfc/rfc9421.txt``,
Appendix B.1.4 and B.2.6) rather than from any summary of it — a summarizing fetch of that same
appendix returned a fabricated public key and a fabricated component list on 2026-09-03, both
plausible enough to pass a reading.

What makes the SIGN side testable here, rather than only verification: B.1.4 publishes the private
key, Ed25519 is deterministic, and ``created`` is pinned in the example. So signing the RFC's own
request with the RFC's own key must reproduce the RFC's own ``Signature`` header byte for byte.

Note what this vector does NOT cover: ``@query`` and ``content-digest``. Its test request carries
``?param=Value&Pet=dog`` and a body, and signs neither. The two protections @2hwvpm42 adds beyond
heti therefore have no RFC oracle at all, and are pinned by the Bakobo vectors instead.
"""

from __future__ import annotations

import base64

from fiki import Key, signature_base

# --- RFC 9421 B.1.4, the ed25519 test key, from the JWK form's "d" (base64url, 32 bytes) ---
RFC_SEED = base64.urlsafe_b64decode("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU" + "=")
# The same key pair's public half, rendered through fiki's lens as a non-transferable AID. heti
# pins this identical string for the same RFC key, which is what keeps the two libraries' key
# types interchangeable over one seed.
RFC_AID = "BCa0C4-T__PYlxEvfrxYKyMtvXJRfQgv6Dz7MN3OQ9G7"

# --- RFC 9421 B.2, the "test-request" message ---
RFC_METHOD = "POST"
RFC_URL = "https://example.com/foo?param=Value&Pet=dog"
RFC_HEADERS = {
    "Host": "example.com",
    "Date": "Tue, 20 Apr 2021 02:07:55 GMT",
    "Content-Type": "application/json",
    "Content-Digest": "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+Ab"
                      "wAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
    "Content-Length": "18",
}

# --- RFC 9421 B.2.6, signing that request with ed25519 ---
RFC_COVERED = ("date", "@method", "@path", "@authority", "content-type", "content-length")
RFC_CREATED = 1618884473
RFC_KEYID = "test-key-ed25519"
RFC_LABEL = "sig-b26"

RFC_BASE = (
    '"date": Tue, 20 Apr 2021 02:07:55 GMT\n'
    '"@method": POST\n'
    '"@path": /foo\n'
    '"@authority": example.com\n'
    '"content-type": application/json\n'
    '"content-length": 18\n'
    '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" '
    '"content-length");created=1618884473;keyid="test-key-ed25519"'
)
RFC_SIGNATURE = (
    "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="
)


def test_rfc_seed_yields_the_published_public_key():
    """Bind the private key to the published public half before trusting either.

    A mistyped seed would otherwise surface as a signature mismatch, where the base builder is the
    natural suspect and the key is not.
    """
    assert Key.from_seed(RFC_SEED).aid == RFC_AID


def test_signature_base_matches_rfc9421_b_2_6():
    """The base is what the RFC actually prints, so a mismatch localizes to the builder."""
    base = signature_base(
        method=RFC_METHOD,
        url=RFC_URL,
        headers=RFC_HEADERS,
        covered=RFC_COVERED,
        created=RFC_CREATED,
        keyid=RFC_KEYID,
    )
    assert base.decode("utf-8") == RFC_BASE


def test_signing_rfc9421_b_2_6_reproduces_the_published_signature():
    """Ed25519 is deterministic, so this is byte equality rather than a verification round trip."""
    base = signature_base(
        method=RFC_METHOD,
        url=RFC_URL,
        headers=RFC_HEADERS,
        covered=RFC_COVERED,
        created=RFC_CREATED,
        keyid=RFC_KEYID,
    )
    signature = Key.from_seed(RFC_SEED).sign(base)
    assert base64.b64encode(signature).decode("ascii") == RFC_SIGNATURE

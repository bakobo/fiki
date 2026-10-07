using System;
using System.Collections.Generic;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// Conformance against RFC 9421's own Appendix B vectors (this.i @5gf6r08f), mirroring
    /// py/tests/test_rfc9421_conformance.py.
    /// </summary>
    /// <remarks>
    /// Every literal here was read verbatim from https://www.rfc-editor.org/rfc/rfc9421.txt,
    /// Appendix B.1.4 and B.2.6, and agrees byte for byte with the same literals in fiki-py's suite
    /// and with vectors/keri/rfc9421.json. B.1.4 publishes the private key and Ed25519 is
    /// deterministic, so signing the RFC's request with the RFC's key must reproduce the RFC's
    /// Signature header exactly.
    /// </remarks>
    public class RfcConformanceTests
    {
        // RFC 9421 B.1.4, the ed25519 test key: the JWK form's "d" (base64url, 32 bytes).
        internal static readonly byte[] RfcSeed = Bytes.FromB64Url("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU");

        // The same key pair's public half through fiki's lens. heti pins this identical string.
        internal const string RfcAid = "BCa0C4-T__PYlxEvfrxYKyMtvXJRfQgv6Dz7MN3OQ9G7";

        // RFC 9421 B.2, the "test-request" message.
        internal const string RfcMethod = "POST";
        internal const string RfcUrl = "https://example.com/foo?param=Value&Pet=dog";

        internal static readonly KeyValuePair<string, string>[] RfcHeaders =
        {
            new("Host", "example.com"),
            new("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            new("Content-Type", "application/json"),
            new("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"),
            new("Content-Length", "18"),
        };

        // RFC 9421 B.2.6, signing that request with ed25519.
        internal static readonly string[] RfcCovered = { "date", "@method", "@path", "@authority", "content-type", "content-length" };
        internal const long RfcCreated = 1618884473;
        internal const string RfcKeyId = "test-key-ed25519";

        internal const string RfcBase =
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n" +
            "\"@method\": POST\n" +
            "\"@path\": /foo\n" +
            "\"@authority\": example.com\n" +
            "\"content-type\": application/json\n" +
            "\"content-length\": 18\n" +
            "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" " +
            "\"content-length\");created=1618884473;keyid=\"test-key-ed25519\"";

        internal const string RfcSignature =
            "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==";

        private static byte[] Base() => HttpSignatures.SignatureBase(
            RfcMethod, RfcUrl, RfcHeaders, RfcCovered, RfcCreated, RfcKeyId);

        [Fact]
        public void SigningRfc9421B26ReproducesThePublishedSignature()
        {
            // Ed25519 is deterministic, so this is byte equality rather than a round trip.
            var signature = Key.FromSeed(RfcSeed).Sign(Base());
            Assert.Equal(RfcSignature, Convert.ToBase64String(signature));
        }

        [Fact]
        public void TheRfcSeedYieldsThePublishedPublicKey()
        {
            // A mistyped seed would otherwise surface as a signature mismatch, where the base
            // builder is the natural suspect and the key is not.
            Assert.Equal(RfcAid, Key.FromSeed(RfcSeed).Aid);
        }

        [Fact]
        public void TheSignatureBaseMatchesRfc9421B26()
        {
            Assert.Equal(RfcBase, Bytes.Text(Base()));
        }
    }
}

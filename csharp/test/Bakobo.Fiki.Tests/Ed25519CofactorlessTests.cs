using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text.Json;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// The hand-written cofactorless Ed25519 check, alone (review B3). RFC 8032 section 7.1's TEST 1
    /// to 3 are copied verbatim from https://www.rfc-editor.org/rfc/rfc8032.txt; the mixed-order
    /// cases are the shared vectors' own, whose signatures only the equation tells apart.
    /// </summary>
    public class Ed25519CofactorlessTests
    {
        public static IEnumerable<object[]> Rfc8032() => new[]
        {
            // -----TEST 1: MESSAGE (length 0 bytes)
            new object[]
            {
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            },
            // -----TEST 2: MESSAGE (length 1 byte)
            new object[]
            {
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            },
            // -----TEST 3: MESSAGE (length 2 bytes)
            new object[]
            {
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            },
        };

        [Theory]
        [MemberData(nameof(Rfc8032))]
        public void Rfc8032sTestVectorsVerify(string publicKey, string message, string signature) =>
            Assert.True(Ed25519Cofactorless.Verify(Bytes.FromHex(publicKey), Bytes.FromHex(message), Bytes.FromHex(signature)));

        [Theory]
        [MemberData(nameof(Rfc8032))]
        public void Rfc8032sTestVectorsRefuseAnotherMessage(string publicKey, string message, string signature) =>
            Assert.False(Ed25519Cofactorless.Verify(Bytes.FromHex(publicKey), Bytes.FromHex(message + "00"), Bytes.FromHex(signature)));

        // p = 2^255 - 19 and L = 2^252 + 27742317777372353535851937790883648493, little-endian, as
        // RFC 8032 section 6's reference code encodes them (vectors/rfc8032.py, int.to_bytes).
        private const string FieldPrime = "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
        private const string GroupOrder = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

        private static readonly byte[] Key1 = Bytes.FromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        private static readonly byte[] Signature1 = Bytes.FromHex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        private static byte[] WithR(string r) => Bytes.FromHex(r).Concat(Signature1.Skip(32)).ToArray();

        [Fact]
        public void AnSAtOrAboveTheGroupOrderIsRefused()
        {
            // RFC 8032 section 5.1.7 step 1: S + L verifies under any equation that reduces S.
            var s = new BigInteger(Signature1.Skip(32).Concat(new byte[] { 0 }).ToArray()) + BigInteger.Pow(2, 252)
                + BigInteger.Parse("27742317777372353535851937790883648493", System.Globalization.CultureInfo.InvariantCulture);
            var bytes = s.ToByteArray().Concat(new byte[32]).Take(32).ToArray();
            Assert.False(Ed25519Cofactorless.Verify(Key1, new byte[0], Signature1.Take(32).Concat(bytes).ToArray()));
            Assert.False(Ed25519Cofactorless.Verify(Key1, new byte[0], Signature1.Take(32).Concat(Bytes.FromHex(GroupOrder)).ToArray()));
        }

        [Fact]
        public void AKeyOrRThatDoesNotDecompressIsRefused()
        {
            // y = p is not canonical; y = 2 has no x on the curve (both found with RFC 8032's
            // reference point_decompress, which returns None for each).
            var y2 = "0200000000000000000000000000000000000000000000000000000000000000";
            Assert.False(Ed25519Cofactorless.Verify(Bytes.FromHex(FieldPrime), new byte[0], Signature1));
            Assert.False(Ed25519Cofactorless.Verify(Bytes.FromHex(y2), new byte[0], Signature1));
            Assert.False(Ed25519Cofactorless.Verify(Key1, new byte[0], WithR(FieldPrime)));
            Assert.False(Ed25519Cofactorless.Verify(Key1, new byte[0], WithR(y2)));
        }

        [Fact]
        public void DecompressionIsStrictAboutAZeroX()
        {
            // y = 1, x = 0 is the neutral element; with the sign bit set it is no encoding at all
            // (section 5.1.3 step 4).
            Assert.NotNull(Ed25519Cofactorless.Decompress(Bytes.FromHex("0100000000000000000000000000000000000000000000000000000000000000"), 0));
            Assert.Null(Ed25519Cofactorless.Decompress(Bytes.FromHex("0100000000000000000000000000000000000000000000000000000000000080"), 0));
            // y = p - 1 with the sign bit set: the reference code's unreduced x^2 accepts it, and
            // section 5.1.3 step 4 refuses it, as this port does (the documented difference).
            Assert.NotNull(Ed25519Cofactorless.Decompress(Bytes.FromHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), 0));
            Assert.Null(Ed25519Cofactorless.Decompress(Bytes.FromHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), 0));
            // An R of the neutral element decodes, and the equation then fails.
            Assert.False(Ed25519Cofactorless.Verify(Key1, new byte[0], WithR("0100000000000000000000000000000000000000000000000000000000000000")));
        }

        [Fact]
        public void PointsAreComparedProjectively()
        {
            BigInteger[] Point(long x, long y, long z) => new[] { new BigInteger(x), new BigInteger(y), new BigInteger(z), BigInteger.Zero };
            Assert.True(Ed25519Cofactorless.Equal(Point(0, 1, 1), Point(0, 2, 2)));
            Assert.False(Ed25519Cofactorless.Equal(Point(0, 1, 1), Point(0, -1, 1)));
            Assert.False(Ed25519Cofactorless.Equal(Point(1, 1, 1), Point(0, 1, 1)));
        }

        public static IEnumerable<object[]> MixedOrder() => new[]
        {
            new object[] { "refusals.json", "cofactored-only-signature-under-an-honest-key", false },
            new object[] { "refusals.json", "mixed-order-key-the-cofactorless-check-refuses", false },
            new object[] { "accepts.json", "cofactorless-accept-with-torsion-in-r", true },
            new object[] { "accepts.json", "mixed-order-key-the-cofactorless-check-accepts", true },
        };

        [Theory]
        [MemberData(nameof(MixedOrder))]
        public void TheSharedVectorsMixedOrderCasesAreToldApart(string file, string id, bool cofactorless)
        {
            var c = Repo.Json("vectors", file).GetProperty("cases").EnumerateArray().Single(x => x.GetProperty("id").GetString() == id);
            var headers = c.GetProperty("headers");
            var input = headers.GetProperty("Signature-Input").GetString()!;
            Assert.StartsWith("sig=(\"@method\" \"@authority\" \"@path\" \"@query\");created=1700000000;alg=\"ed25519\";keyid=\"", input, StringComparison.Ordinal);
            var keyId = input.Split('"')[11];
            var signature = Convert.FromBase64String(headers.GetProperty("Signature").GetString()!.Split(':')[1]);
            var signatureBase = HttpSignatures.SignatureBase(c.GetProperty("method").GetString()!, c.GetProperty("url").GetString()!,
                new Dictionary<string, string>(), HttpSignatures.DefaultCovered, 1700000000, keyId, alg: "ed25519");
            var key = Bytes.FromB64Url(keyId);

            Assert.Equal(cofactorless, Ed25519Cofactorless.Verify(key, signatureBase, signature));
            // BouncyCastle's cofactored check takes all four, which is why it needs this half.
            Assert.True(Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.Verify(signature, 0, key, 0, signatureBase, 0, signatureBase.Length));
            Assert.Equal(cofactorless, new PublicKey(key).Verify(signature, signatureBase));
        }
    }
}

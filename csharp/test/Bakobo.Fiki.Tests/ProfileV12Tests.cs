using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// What KERI profile version 1.2 asks of the C# port beyond 1.1 (this.i @37rktct3, @84nt4je0),
    /// mirroring py/tests/test_profile_v1_2.py.
    /// </summary>
    /// <remarks>
    /// Under a resolver, where the keyid is an AID, a B keyid's key is the prefix's and must lie in
    /// the prime-order subgroup, and an AID is any of keripy's PreDex prefix codes (@37rktct3).
    /// Request content no header announced is refused at the body stage, after the signature and
    /// freshness checks (@84nt4je0). The mixed-order oracle builds its torsion point from the curve
    /// equation (<see cref="SmallOrderTests"/>'s order-8 points) and adds it in affine coordinates
    /// with BigInteger, not through BouncyCastle, so a wrong check and a wrong oracle cannot agree by
    /// sharing a method.
    /// </remarks>
    public class ProfileV12Tests
    {
        private static readonly Key TheKey = Key.FromSeed(Bytes.Range(0, 32));
        private const string Url = "https://keria.example.com/identifiers?type=rot";
        private static readonly byte[] Body = Bytes.Utf8("{\"hello\": \"world\"}");
        private const long At = 1700000000;
        private static readonly BigInteger P = SmallOrderTests.P;
        private static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493", System.Globalization.CultureInfo.InvariantCulture);
        private static readonly string[] Minimum = { "@method", "@path", "@query" };

        private static byte[] Raw(Key key) => Key.VerifyingKey(key.Aid).ToBytes();

        /// <summary>CESR's arithmetic: zero bytes in front to a multiple of three, base64url, and the code in place of the characters those bytes became.</summary>
        private static string Cesr(string code, byte[] data)
        {
            var pad = (3 - data.Length % 3) % 3;
            return code + Bytes.B64Url(new byte[pad].Concat(data).ToArray()).Substring(pad);
        }

        private static byte[] Sha256(byte[] data)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(data);
        }

        private static byte[] Sha512(byte[] data)
        {
            using var sha = SHA512.Create();
            return sha.ComputeHash(data);
        }

        // --- a mixed-order key, built in affine coordinates ---

        private static (BigInteger X, BigInteger Y) AffineAdd((BigInteger X, BigInteger Y) a, (BigInteger X, BigInteger Y) b)
        {
            var t = SmallOrderTests.Mod(SmallOrderTests.D * a.X * b.X * a.Y * b.Y);
            return (SmallOrderTests.Mod((a.X * b.Y + a.Y * b.X) * SmallOrderTests.Inverse(1 + t)),
                SmallOrderTests.Mod((a.Y * b.Y + a.X * b.X) * SmallOrderTests.Inverse(1 - t)));
        }

        private static (BigInteger X, BigInteger Y) Decode(byte[] raw)
        {
            var y = new BigInteger(raw.Concat(new byte[1]).ToArray());
            var sign = !(y >> 255).IsZero;
            y &= (BigInteger.One << 255) - 1;
            var x = SmallOrderTests.Sqrt((y * y - 1) * SmallOrderTests.Inverse(SmallOrderTests.D * y * y + 1))!.Value;
            return (!x.IsEven != sign ? P - x : x, y);
        }

        private static byte[] Encode((BigInteger X, BigInteger Y) point)
        {
            var bytes = point.Y.ToByteArray().Concat(new byte[33]).Take(32).ToArray();
            if (!point.X.IsEven)
            {
                bytes[31] |= 0x80;
            }
            return bytes;
        }

        private static (BigInteger X, BigInteger Y) OrderEight()
        {
            foreach (var p in SmallOrderTests.Torsion())
            {
                var point = p;
                var n = 1;
                while (point != (BigInteger.Zero, BigInteger.One))
                {
                    point = AffineAdd(point, p);
                    n++;
                }
                if (n == 8)
                {
                    return p;
                }
            }
            throw new InvalidOperationException("no point of order 8");
        }

        private static readonly byte[] Mixed = Encode(AffineAdd(Decode(Raw(TheKey)), OrderEight()));
        private static readonly string BMixed = Cesr("B", Mixed);
        private static readonly string BWeak = Cesr("B", new byte[] { 1 }.Concat(new byte[31]).ToArray());
        private static readonly string EAid = Cesr("E", Sha256(Bytes.Utf8("a transferable AID")));

        private sealed class Msg
        {
            public byte[]? Body;
            public Dictionary<string, string> Headers = new Dictionary<string, string>();

            public Verdict Verify(Func<VerifyOptions, VerifyOptions> with) =>
                HttpSignatures.VerifyRequest("POST", Url, Headers, with(Verifying.MaxAge(300).WithNow(At).WithBody(Body)));

            public FikiException Refused(Func<VerifyOptions, VerifyOptions> with) => Assert.Throws<FikiException>(() => Verify(with));
        }

        private static Msg Sign(string keyId, bool noBody = false, Dictionary<string, string>? headers = null)
        {
            var given = headers ?? new Dictionary<string, string>();
            var message = new Msg { Body = noBody ? null : Body, Headers = new Dictionary<string, string>(given) };
            foreach (var h in HttpSignatures.SignRequest(TheKey, "POST", Url, given, message.Body, created: At, keyId: keyId))
            {
                message.Headers[h.Key] = h.Value;
            }
            return message;
        }

        private static byte[]? Never(string keyId) => throw new InvalidOperationException($"the resolver was asked about {keyId}");

        [Fact]
        public void TheOracleKeyIsOnTheCurveAndNotInThePrimeOrderSubgroup()
        {
            var point = Decode(Mixed);
            Assert.Equal(SmallOrderTests.Mod(1 + SmallOrderTests.D * point.X * point.X * point.Y * point.Y),
                SmallOrderTests.Mod(-point.X * point.X + point.Y * point.Y));
            var multiple = point;
            var n = L - 1;
            var acc = (X: BigInteger.Zero, Y: BigInteger.One);
            while (!n.IsZero)
            {
                // [L]P by double-and-add in affine coordinates
                if (!n.IsEven)
                {
                    acc = AffineAdd(acc, multiple);
                }
                multiple = AffineAdd(multiple, multiple);
                n >>= 1;
            }
            Assert.NotEqual((BigInteger.Zero, BigInteger.One), AffineAdd(acc, point));
            // ...and the signer's own key, which it was built from, is in the subgroup.
            Assert.True(Aids.IsSubgroupKey(Raw(TheKey)));
        }

        // --- B keyids under a resolver: the prefix's key, never the resolver's (@37rktct3) ---

        [Fact]
        public void ABKeyidIsVerifiedFromItsPrefixWithoutAskingTheResolver()
        {
            var verdict = Sign(TheKey.Aid).Verify(o => o.WithResolver(Never));
            Assert.Equal(TheKey.Aid, verdict.KeyId);
            Assert.Equal(TheKey.Aid, verdict.Aid);
        }

        [Fact]
        public void AMixedOrderBKeyidIsMalformedUnderAResolver()
        {
            var caught = Sign(BMixed).Refused(o => o.WithResolver(Never));
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
            Assert.Equal(BMixed, caught.KeyId);
            Assert.Contains("mixed order", caught.Message);
        }

        /// <summary>An expected AID names its key by an AID as a B keyid does, so the key must lie in the subgroup.</summary>
        [Fact]
        public void AMixedOrderExpectedAidIsMalformed()
        {
            var caught = Sign(BMixed).Refused(o => o.WithExpectedAid(BMixed));
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
            Assert.Equal(BMixed, caught.KeyId);
            Assert.Contains("mixed order", caught.Message);
        }

        [Theory]
        [InlineData("small-order")]
        [InlineData("mixed-order")]
        public void AWeakBKeyidIsMalformedBeforeTheExpectedKeyidIsCompared(string which)
        {
            var keyId = which == "small-order" ? BWeak : BMixed;
            var caught = Sign(keyId).Refused(o => o.WithResolver(Never).WithExpectedKeyId(EAid));
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
            Assert.Equal(keyId, caught.KeyId);
        }

        [Fact]
        public void AMixedOrderKeyFromAResolverIsMalformed()
        {
            var caught = Sign(EAid).Refused(o => o.WithResolver(k => k == EAid ? Mixed : null));
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
            Assert.Equal(EAid, caught.KeyId);
        }

        [Fact]
        public void AMixedOrderRawKeyidIsStillFikisOwnLensAndNotRefusedForItsOrder()
        {
            // vectors_format 4 pins acceptance of a mixed-order raw keyid (@5r75ff4m); only an AID's
            // key must lie in the subgroup, so this one reaches the signature check.
            Assert.Equal(FikiErrorKind.SignatureMismatch, Sign(Bytes.B64Url(Mixed)).Refused(o => o).Kind);
        }

        // --- an AID is any of keripy's PreDex codes (@37rktct3) ---

        private static readonly Dictionary<string, int> PreDex = new Dictionary<string, int>
        {
            { "B", 32 }, { "D", 32 }, { "E", 32 }, { "F", 32 }, { "G", 32 }, { "H", 32 }, { "I", 32 },
            { "0D", 64 }, { "0E", 64 }, { "0F", 64 }, { "0G", 64 },
            { "1AAA", 33 }, { "1AAB", 33 }, { "1AAI", 33 }, { "1AAJ", 33 },
            { "1AAC", 57 }, { "1AAD", 57 }, { "1AAE", 114 },
        };

        public static IEnumerable<object[]> PreDexCodes() => PreDex.Keys.Select(k => new object[] { k });

        [Theory]
        [MemberData(nameof(PreDexCodes))]
        public void EveryPreDexCodeSpellsAWellFormedAid(string code)
        {
            var digest = Sha512(Bytes.Utf8(code));
            var keyId = Cesr(code, digest.Concat(digest).Take(PreDex[code]).ToArray());
            Assert.True(Aids.WellFormed(keyId));
            Assert.Equal(code, Aids.AidCode(keyId));
            Assert.False(Aids.WellFormed(keyId.Substring(0, keyId.Length - 1)));
            Assert.False(Aids.WellFormed(keyId + "A"));
        }

        [Theory]
        [InlineData("code-A", "A")]
        [InlineData("code-J", "J")]
        [InlineData("code-0A", "0A")]
        [InlineData("code-1AAF", "1AAF")]
        [InlineData("1AAD-short", "1AADs")]
        [InlineData("0D-pad-bit-1", "0Dg")]
        [InlineData("0D-pad-bit-2", "0DQ")]
        [InlineData("code-1-alone", "1")]
        [InlineData("code-0-alone", "0")]
        [InlineData("non-alphabet", "D!")]
        [InlineData("non-ascii-letter", "é")]
        public void OtherCodesAndNonCanonicalSpellingsAreNotAids(string name, string shape)
        {
            var keyId = shape switch
            {
                "A" => "A" + new string('A', 43),
                "J" => "J" + new string('A', 43),
                "0A" => "0A" + new string('A', 86),
                "1AAF" => "1AAF" + new string('A', 44),
                "1AADs" => "1AAD" + new string('A', 75),
                "0Dg" => "0D" + "g" + new string('A', 85),
                "0DQ" => "0D" + "Q" + new string('A', 85),
                "D!" => "D" + new string('!', 43),
                "é" => "é" + new string('A', 43),
                _ => shape,
            };
            Assert.False(Aids.WellFormed(keyId), name);
        }

        [Fact]
        public void AnEd448TransferableKeyidWithNoKeyStateIsAnUnknownKey()
        {
            var keyId = Cesr("1AAD", Bytes.Range(0, 57));
            var calls = new List<string>();
            var caught = Sign(keyId).Refused(o => o.WithResolver(k =>
            {
                calls.Add(k);
                return null;
            }));
            Assert.Equal(FikiErrorKind.UnknownKey, caught.Kind);
            Assert.Equal(new[] { keyId }, calls);
        }

        [Theory]
        [InlineData("1AAA", 33)]
        [InlineData("1AAC", 57)]
        [InlineData("1AAI", 33)]
        public void ANonTransferableKeyidOtherThanBIsAnUnsupportedAlgorithm(string code, int size)
        {
            var keyId = Cesr(code, new byte[] { 2 }.Concat(Bytes.Range(0, size - 1)).ToArray());
            var caught = Sign(keyId).Refused(o => o.WithResolver(Never));
            Assert.Equal(FikiErrorKind.UnsupportedAlgorithm, caught.Kind);
            Assert.Null(caught.Alg);
        }

        [Fact]
        public void ANonTransferableKeyidOtherThanTheExpectedOneIsUnknownFirst()
        {
            var keyId = Cesr("1AAA", new byte[] { 2 }.Concat(Bytes.Range(0, 32)).ToArray());
            Assert.Equal(FikiErrorKind.UnknownKey, Sign(keyId).Refused(o => o.WithResolver(Never).WithExpectedKeyId(EAid)).Kind);
        }

        // --- content no header announced, at the body stage (@84nt4je0) ---

        private static Msg Unannounced()
        {
            var message = Sign(TheKey.Aid, noBody: true);
            message.Body = Body;
            return message;
        }

        [Fact]
        public void AnUnannouncedUncoveredRequestBodyIsRefusedAtTheBodyStage()
        {
            var caught = Unannounced().Refused(o => o.WithResolver(Never).WithMinimum(Minimum));
            Assert.Equal(FikiErrorKind.InsufficientCoverage, caught.Kind);
            Assert.Equal("content-digest", caught.Component);
        }

        [Fact]
        public void AnUnannouncedUncoveredRequestBodyComesAfterFreshness() =>
            Assert.Equal(FikiErrorKind.SignatureTooOld,
                Unannounced().Refused(o => o.WithResolver(Never).WithNow(At + 1000).WithMinimum(Minimum)).Kind);

        [Fact]
        public void AnUnannouncedUncoveredRequestBodyComesAfterTheSignature()
        {
            var message = Unannounced();
            message.Headers["Signature-Input"] = message.Headers["Signature-Input"].Replace(";created=", ";nonce=\"x\";created=");
            Assert.Equal(FikiErrorKind.SignatureMismatch, message.Refused(o => o.WithResolver(Never).WithMinimum(Minimum)).Kind);
        }

        [Fact]
        public void AnUnannouncedRequestBodyWithoutAMinimumIsNotRefused() =>
            Assert.Equal(TheKey.Aid, Unannounced().Verify(o => o.WithResolver(Never).WithoutMinimum()).KeyId);

        [Fact]
        public void AnAnnouncedUncoveredRequestBodyIsStillRefusedAtTheCoveredList()
        {
            var message = Sign(TheKey.Aid, noBody: true, headers: new Dictionary<string, string> { { "Content-Length", "18" } });
            var caught = message.Refused(o => o.WithResolver(Never).WithNow(At + 1000).WithMinimum(Minimum));
            Assert.Equal(FikiErrorKind.InsufficientCoverage, caught.Kind);
        }

        [Fact]
        public void AnUncoveredResponseBodyIsRefusedAtTheCoveredListByItsContent()
        {
            // A client holds the response's content before verifying it, so the covered-list check
            // judges it there, ahead of the signature (profile section 9, step 12).
            var request = new Request("GET", Url, new Dictionary<string, string>(), null);
            var headers = HttpSignatures.SignResponse(TheKey, 200, request, new Dictionary<string, string>(), null, created: At, keyId: TheKey.Aid);
            var caught = Assert.Throws<FikiException>(() => HttpSignatures.VerifyResponse(201, headers,
                VerifyOptions.MaxAge(300).WithNow(At).WithBody(Bytes.Utf8("{\"done\": true}")).WithRequest(request)
                    .WithResolver(Never).WithExpectedKeyId(TheKey.Aid)));
            Assert.Equal(FikiErrorKind.InsufficientCoverage, caught.Kind);
        }
    }
}

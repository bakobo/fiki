using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Xunit;

namespace Bakobo.Fiki.Tests
{
    /// <summary>
    /// A small-order Ed25519 public key is refused as MalformedKey when the key is decoded or
    /// resolved, and is never attempted as a verification (fail closed; decided across ports
    /// 2026-10-07). Against such a key a signature anyone can write verifies under OpenSSL, which
    /// fiki-py uses: the identity point with R = identity and S = 0 is accepted for every message.
    /// </summary>
    /// <remarks>
    /// The points are derived here from the curve equation with BigInteger, independently of
    /// BouncyCastle, so the test does not borrow its oracle from the code under test.
    /// edwards25519 is -x^2 + y^2 = 1 + d x^2 y^2 over p = 2^255 - 19, with cofactor 8, so its torsion
    /// is cyclic of order 8 and has exactly 8 points: the identity (0, 1), the order-2 point (0, -1),
    /// two of order 4 with y = 0, and four of order 8, whose doubles are the order-4 points. Doubling
    /// gives y = 0 exactly when x^2 = -y^2, which with the curve equation is d y^4 + 2 y^2 - 1 = 0.
    /// </remarks>
    public class SmallOrderTests
    {
        private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
        private static readonly BigInteger D = Mod(-121665 * Inverse(121666));
        private static readonly BigInteger SqrtMinusOne = BigInteger.ModPow(2, (P - 1) / 4, P);

        private static BigInteger Mod(BigInteger a) => ((a % P) + P) % P;

        private static BigInteger Inverse(BigInteger a) => BigInteger.ModPow(Mod(a), P - 2, P);

        /// <summary>A square root mod p (p = 5 mod 8), or null when a is not a square.</summary>
        private static BigInteger? Sqrt(BigInteger a)
        {
            a = Mod(a);
            var root = BigInteger.ModPow(a, (P + 3) / 8, P);
            if (Mod(root * root) == a)
            {
                return root;
            }
            root = Mod(root * SqrtMinusOne);
            return Mod(root * root) == a ? root : (BigInteger?)null;
        }

        /// <summary>The 32-byte encoding: y little-endian, with x's low bit in the top bit.</summary>
        private static byte[] Encode(BigInteger y, bool xOdd)
        {
            var bytes = y.ToByteArray().Concat(new byte[33]).Take(32).ToArray();
            if (xOdd)
            {
                bytes[31] |= 0x80;
            }
            return bytes;
        }

        private static bool OnCurve(BigInteger x, BigInteger y) =>
            Mod(-x * x + y * y) == Mod(1 + D * x * x * y * y);

        /// <summary>The eight small-order points, as (x, y).</summary>
        private static List<(BigInteger X, BigInteger Y)> Torsion()
        {
            var points = new List<(BigInteger, BigInteger)> { (0, 1), (0, P - 1) };
            var i = SqrtMinusOne;
            points.Add((i, 0));
            points.Add((P - i, 0));
            // y^2 = (-1 +- sqrt(1 + d)) / d; exactly one sign gives a square y^2 with a square x^2.
            var root = Sqrt(1 + D)!.Value;
            foreach (var y2 in new[] { Mod((-1 + root) * Inverse(D)), Mod((-1 - root) * Inverse(D)) })
            {
                var y = Sqrt(y2);
                var x = y == null ? null : Sqrt(-y2);
                if (y != null && x != null)
                {
                    foreach (var py in new[] { y.Value, P - y.Value })
                    {
                        points.Add((x.Value, py));
                        points.Add((P - x.Value, py));
                    }
                }
            }
            return points;
        }

        /// <summary>Every encoding of a small-order point: the 8 canonical ones and the 6 that are not.</summary>
        public static IEnumerable<object[]> Encodings()
        {
            var canonical = Torsion().Select(p => (Name: $"y={(p.Y < 2 || p.Y > P - 2 ? p.Y.ToString() : "...")}", Bytes: Encode(p.Y, !p.X.IsEven)));
            var noncanonical = new List<(string, byte[])>
            {
                // y + p fits in 255 bits only for y < 19, so only y = 0 and y = 1 have one.
                ("y=p (0), x even", Encode(P, false)),
                ("y=p (0), x odd", Encode(P, true)),
                ("y=p+1 (1), sign 0", Encode(P + 1, false)),
                ("y=p+1 (1), sign 1", Encode(P + 1, true)),
                // x = 0 has no odd root, so a set sign bit on y = 1 or y = -1 is a second spelling.
                ("y=1, sign 1", Encode(1, true)),
                ("y=-1, sign 1", Encode(P - 1, true)),
            };
            return canonical.Concat(noncanonical).Select(e => new object[] { e.Item1, Bytes.ToHex(e.Item2) });
        }

        [Fact]
        public void TheDerivationFindsEightDistinctPointsOnTheCurve()
        {
            var points = Torsion();
            Assert.Equal(8, points.Distinct().Count());
            Assert.All(points, p => Assert.True(OnCurve(p.X, p.Y)));
            Assert.Equal(14, Encodings().Count());
            Assert.Equal(14, Encodings().Select(e => (string)e[1]).Distinct().Count());
            // The well-known identity and order-8 encodings, as a check on the arithmetic.
            Assert.Contains(Encodings(), e => (string)e[1] == "0100000000000000000000000000000000000000000000000000000000000000");
            Assert.Contains(Encodings(), e => (string)e[1] == "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
        }

        private static readonly Key Signer = Key.FromSeed(Bytes.Range(0, 32));
        private const string Url = "https://api.example.com/things?limit=1";
        private static readonly byte[] Body = Bytes.Utf8("{\"hello\": \"world\"}");
        private static readonly byte[] Identity = Bytes.FromHex("0100000000000000000000000000000000000000000000000000000000000000");

        /// <summary>A real request signed under <paramref name="keyId"/>, its signature replaced by the universal forgery R = identity, S = 0.</summary>
        private static Dictionary<string, string> Forged(string keyId, string alg = "ed25519")
        {
            var headers = HttpSignatures.SignRequest(Signer, "POST", Url, body: Body, created: 1700000000, keyId: keyId).ToDictionary(h => h.Key, h => h.Value);
            headers["Signature"] = "sig=:" + Convert.ToBase64String(Identity.Concat(new byte[32]).ToArray()) + ":";
            headers["Signature-Input"] = headers["Signature-Input"].Replace("alg=\"ed25519\"", $"alg=\"{alg}\"");
            return headers;
        }

        private static FikiException Refused(Dictionary<string, string> headers, VerifyOptions? options = null) =>
            Assert.Throws<FikiException>(() => HttpSignatures.VerifyRequest("POST", Url, headers, (options ?? Verifying.DecliningFreshness()).WithBody(Body)));

        [Fact]
        public void TheIdentityKeyidWithTheUniversalForgeryIsAMalformedKey()
        {
            var keyId = Bytes.B64Url(Identity);
            var caught = Refused(Forged(keyId));
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
            Assert.Equal(keyId, caught.KeyId);
        }

        [Fact]
        public void ASmallOrderKeyIsRefusedBeforeTheAlgorithm() =>
            Assert.Equal(FikiErrorKind.MalformedKey, Refused(Forged(Bytes.B64Url(Identity), alg: "rsa-pss-sha512")).Kind);

        [Theory]
        [MemberData(nameof(Encodings))]
        public void EveryEncodingOfASmallOrderPointIsAMalformedKeyid(string name, string hex)
        {
            var keyId = Bytes.B64Url(Bytes.FromHex(hex));
            Assert.Equal(FikiErrorKind.MalformedKey, Refused(Forged(keyId)).Kind);
            Assert.NotNull(name);
        }

        [Theory]
        [MemberData(nameof(Encodings))]
        public void EveryEncodingOfASmallOrderPointIsAMalformedResolvedKey(string name, string hex)
        {
            var aid = Aids.Qb64('E', new byte[32]);
            var caught = Refused(Forged(aid), Verifying.DecliningFreshness().WithResolver(_ => Bytes.FromHex(hex)));
            Assert.Equal(FikiErrorKind.MalformedKey, caught.Kind);
            Assert.Equal(aid, caught.KeyId);
            Assert.NotNull(name);
        }

        [Theory]
        [MemberData(nameof(Encodings))]
        public void ASmallOrderAidIsAMalformedKeyAndToAidWillNotRenderOne(string name, string hex)
        {
            var raw = Bytes.FromHex(hex);
            var aid = Aids.Qb64('B', raw);
            Assert.Equal(FikiErrorKind.MalformedKey, Assert.Throws<FikiException>(() => Key.VerifyingKey(aid)).Kind);
            Assert.Equal(FikiErrorKind.MalformedKey, Refused(Forged(Bytes.B64Url(Key.VerifyingKey(Signer.Aid).ToBytes())),
                Verifying.DecliningFreshness().WithExpectedAid(aid)).Kind);
            Assert.Throws<ArgumentException>(() => Key.ToAid(raw));
            Assert.NotNull(name);
        }

        [Fact]
        public void AnOffCurveKeyIsAMalformedKeyToo()
        {
            // The check that refuses small-order points also refuses a y with no x on the curve:
            // such bytes are not an Ed25519 public key at all.
            BigInteger y = 2;
            while (Sqrt(Mod((y * y - 1) * Inverse(D * y * y + 1))) != null)
            {
                y++;
            }
            var keyId = Bytes.B64Url(Encode(y, false));
            Assert.Equal(FikiErrorKind.MalformedKey, Refused(Forged(keyId)).Kind);
        }

        [Fact]
        public void ARealKeyStillVerifies()
        {
            var headers = HttpSignatures.SignRequest(Signer, "POST", Url, body: Body);
            Assert.Equal(Signer.Aid, HttpSignatures.VerifyRequest("POST", Url, headers, Verifying.MaxAge(60).WithBody(Body)).Aid);
            Assert.Equal(Signer.Aid, Key.ToAid(Key.VerifyingKey(Signer.Aid).ToBytes()));
        }
    }
}

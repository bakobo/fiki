using System.Numerics;
using System.Security.Cryptography;

namespace Bakobo.Fiki
{
    /// <summary>
    /// The cofactorless Ed25519 equation, [S]B = R + [k]A with S &lt; L, ported from RFC 8032
    /// section 6's reference code (vendored verbatim at vectors/rfc8032.py).
    /// </summary>
    /// <remarks>
    /// BouncyCastle checks the cofactored equation, [8][S]B = [8]R + [8][k]A, which RFC 8032 section
    /// 5.1.7 also permits, so it accepts signatures that OpenSSL, Go, dalek and the JDK refuse. fiki
    /// pins the cofactorless one (this.i, "Every port accepts exactly the signatures the
    /// cofactorless Ed25519 equation accepts"). <see cref="PublicKey.Verify"/> accepts only when
    /// BouncyCastle AND this check pass, so a defect here can cause a false refusal but never a
    /// forgery. Not constant-time, and need not be: it handles only public values.
    /// <para>
    /// One deliberate difference from section 6's code: decompression reduces x² modulo p before
    /// testing it for zero, so y = p - 1 with the sign bit set, a second encoding of the point
    /// (0, -1), fails as section 5.1.3 step 4 says it must. The reference code tests the unreduced
    /// product and accepts it. Being stricter can only refuse, which is the safe direction.
    /// </para>
    /// </remarks>
    internal static class Ed25519Cofactorless
    {
        // Base field Z_p.
        private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

        // Curve constant.
        private static readonly BigInteger D = Mod(-121665 * Inv(121666));

        // Group order.
        private static readonly BigInteger Q = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493", System.Globalization.CultureInfo.InvariantCulture);

        // Square root of -1.
        private static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);

        // The base point, in extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, x*y = T/Z.
        private static readonly BigInteger[] G = BasePoint();

        private static BigInteger[] BasePoint()
        {
            var y = Mod(4 * Inv(5));
            var x = RecoverX(y, false)!.Value;
            return new[] { x, y, BigInteger.One, Mod(x * y) };
        }

        /// <summary>Python's %, which is never negative for a positive modulus.</summary>
        private static BigInteger Mod(BigInteger x)
        {
            var r = BigInteger.Remainder(x, P);
            return r.Sign < 0 ? r + P : r;
        }

        private static BigInteger Inv(BigInteger x) => BigInteger.ModPow(x, P - 2, P);

        private static BigInteger[] Add(BigInteger[] p, BigInteger[] q)
        {
            var a = Mod((p[1] - p[0]) * (q[1] - q[0]));
            var b = Mod((p[1] + p[0]) * (q[1] + q[0]));
            var c = Mod(2 * p[3] * q[3] * D);
            var d = Mod(2 * p[2] * q[2]);
            var e = b - a;
            var f = d - c;
            var g = d + c;
            var h = b + a;
            return new[] { Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h) };
        }

        private static BigInteger[] Multiply(BigInteger s, BigInteger[] p)
        {
            var q = new[] { BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero };   // the neutral element
            while (s.Sign > 0)
            {
                if (!s.IsEven)
                {
                    q = Add(q, p);
                }
                p = Add(p, p);
                s >>= 1;
            }
            return q;
        }

        internal static bool Equal(BigInteger[] p, BigInteger[] q) =>
            Mod(p[0] * q[2] - q[0] * p[2]).IsZero && Mod(p[1] * q[2] - q[1] * p[2]).IsZero;

        /// <summary>The x-coordinate for <paramref name="y"/> whose low bit is <paramref name="sign"/>, or null when there is none.</summary>
        private static BigInteger? RecoverX(BigInteger y, bool sign)
        {
            if (y >= P)
            {
                return null;
            }
            var x2 = Mod((y * y - 1) * Inv(D * y * y + 1));
            if (x2.IsZero)
            {
                return sign ? (BigInteger?)null : BigInteger.Zero;
            }
            var x = BigInteger.ModPow(x2, (P + 3) / 8, P);
            if (!Mod(x * x - x2).IsZero)
            {
                x = Mod(x * SqrtM1);
            }
            if (!Mod(x * x - x2).IsZero)
            {
                return null;
            }
            return x.IsEven == sign ? P - x : x;
        }

        /// <summary>Little-endian and unsigned, as RFC 8032 reads every integer.</summary>
        private static BigInteger Unsigned(byte[] bytes, int offset)
        {
            var copy = new byte[33];
            System.Array.Copy(bytes, offset, copy, 0, 32);
            return new BigInteger(copy);
        }

        internal static BigInteger[]? Decompress(byte[] bytes, int offset)
        {
            var y = Unsigned(bytes, offset);
            var sign = (bytes[offset + 31] & 0x80) != 0;
            y &= (BigInteger.One << 255) - 1;
            var x = RecoverX(y, sign);
            return x == null ? null : new[] { x.Value, y, BigInteger.One, Mod(x.Value * y) };
        }

        /// <summary>
        /// True when <paramref name="signature"/>, 64 bytes, satisfies the cofactorless equation
        /// for the 32-byte <paramref name="publicKey"/> over <paramref name="message"/>: A and R
        /// decompress strictly, S &lt; L, and [S]B = R + [k]A with k = SHA-512(R || A || M) mod L.
        /// </summary>
        internal static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
        {
            var a = Decompress(publicKey, 0);
            var r = Decompress(signature, 0);
            var s = Unsigned(signature, 32);
            if (a == null || r == null || s >= Q)
            {
                return false;
            }
            byte[] digest;
            using (var sha = SHA512.Create())
            {
                sha.TransformBlock(signature, 0, 32, null, 0);
                sha.TransformBlock(publicKey, 0, 32, null, 0);
                sha.TransformFinalBlock(message, 0, message.Length);
                digest = sha.Hash!;
            }
            var wide = new byte[65];
            System.Array.Copy(digest, wide, 64);
            var k = BigInteger.Remainder(new BigInteger(wide), Q);
            return Equal(Multiply(s, G), Add(r, Multiply(k, a)));
        }
    }
}

using System;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Bakobo.Fiki
{
    /// <summary>
    /// The AID lens: base64url over the raw 32 bytes behind one leading pad byte, whose character
    /// is then replaced by the CESR code. A few lines of arithmetic rather than a dependency.
    /// </summary>
    internal static class Aids
    {
        internal const int RawLength = 32;
        internal const int Qb64Length = 44;

        // CESR's Ed25519N (non-transferable Ed25519 verification key). fiki decodes this code and no
        // other: a parser that handles one fixed-length code can only be narrower than a full CESR
        // implementation, which is the safe direction for a differential.
        private const char Code = 'B';

        // The one-character codes whose 44-character qb64 carries 32 raw bytes behind one pad byte:
        // Ed25519N (B), Ed25519 transferable (D), and Blake3-256 (E, the usual AID digest).
        private const string SpelledCodes = "BDE";

        private const string UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        internal static string ToAid(byte[] raw) => Qb64(Code, raw);

        /// <summary>
        /// True when 32 bytes are a key fiki will verify with: the canonical encoding of a point on
        /// the curve that is not of small order. BouncyCastle 2.7.0's
        /// <c>Ed25519.ValidatePublicKeyPartial</c> refuses a y of 0, 1 or p - 1 or either order-8
        /// value (every encoding of the 8 small-order points, whatever the sign bit), any y at or
        /// above p, and a y with no x on the curve, which is the set to refuse. It does not refuse a
        /// point with a small-order component beside a large one, which OpenSSL accepts too; the
        /// "Full" variant would, and would refuse more than fiki-py. Against a small-order key a
        /// signature anyone can write verifies, so such a key is malformed, never attempted.
        /// </summary>
        internal static bool IsUsableKey(byte[] raw) => Ed25519.ValidatePublicKeyPartial(raw, 0);

        internal static FikiException Unusable(string keyId) => new FikiException(
            FikiErrorKind.MalformedKey,
            $"The key that \"{keyId}\" names is not a usable Ed25519 public key: it is a point of small order, against which " +
            "anyone can forge a signature, or no canonical point on the curve at all.",
            keyId: keyId);

        /// <summary>A one-character code over 32 raw bytes.</summary>
        internal static string Qb64(char code, byte[] raw)
        {
            var padded = new byte[RawLength + 1];
            Array.Copy(raw, 0, padded, 1, RawLength);
            return code + Base64Url.Encode(padded).Substring(1);
        }

        /// <summary>
        /// The 32 bytes a 44-character qb64 names, or null when it is not the canonical spelling of
        /// any: a character outside base64url, or a non-zero bit in the pad byte the code replaced,
        /// which would give one key a second spelling (bakobo/fiki#4).
        /// </summary>
        private static byte[]? Canonical(string qb64)
        {
            // 43 characters behind the code hold 258 bits: the top two bits of the first are the
            // pad byte's low bits, so they must be zero, and every other bit is key.
            for (var i = 1; i < qb64.Length; i++)
            {
                if (UrlAlphabet.IndexOf(qb64[i]) < 0)
                {
                    return null;
                }
            }
            if (UrlAlphabet.IndexOf(qb64[1]) >= 16)
            {
                return null;
            }
            var decoded = Base64Url.Decode("A" + qb64.Substring(1));
            var raw = new byte[RawLength];
            Array.Copy(decoded, 1, raw, 0, RawLength);
            return raw;
        }

        /// <summary>
        /// True when <paramref name="keyId"/> is shaped like a B, D or E AID and is not its canonical
        /// spelling. fiki checks this before any resolver sees the keyid, so a resolver never has to.
        /// </summary>
        internal static bool Misspelled(string keyId) =>
            keyId.Length == Qb64Length
            && SpelledCodes.IndexOf(keyId[0]) >= 0
            && Canonical(keyId) == null;

        private static FikiException Malformed(string aid, string message) =>
            new FikiException(FikiErrorKind.MalformedKey, message, keyId: aid);

        internal static byte[] VerifyingKey(string aid)
        {
            if (aid.Length != Qb64Length || aid[0] != Code)
            {
                throw new FikiException(
                    FikiErrorKind.MalformedKey,
                    $"A non-transferable AID is {Qb64Length} characters beginning with \"{Code}\"; this one " +
                    $"is {aid.Length} characters and begins with \"{(aid.Length == 0 ? "" : aid.Substring(0, 1))}\".",
                    keyId: aid);
            }
            // py's base64 refuses a non-ASCII str with ValueError before binascii sees it, and
            // verifying_key catches only binascii.Error, so the caller gets a ValueError there.
            foreach (var c in aid)
            {
                if (c > '\x7f')
                {
                    throw new ArgumentException("string argument should contain only ASCII characters", nameof(aid));
                }
            }
            var tail = aid.Substring(1);
            foreach (var c in tail)
            {
                if (UrlAlphabet.IndexOf(c) < 0 && "+/=".IndexOf(c) < 0)
                {
                    throw Malformed(aid, $"The AID \"{aid}\" is not valid base64url.");
                }
            }
            // "=" is in base64's alphabet, so a strict decoder accepts one or two of them at the end
            // and yields 32 or 31 bytes: short of a key, from a string of the right length and code.
            var padding = tail.Length - tail.TrimEnd('=').Length;
            if (tail.IndexOf('=') >= 0)
            {
                throw Malformed(aid, padding > 2 || tail.TrimEnd('=').IndexOf('=') >= 0
                    ? $"The AID \"{aid}\" is not valid base64url."
                    : $"The AID \"{aid}\" does not decode to a {RawLength}-byte key.");
            }
            var raw = Canonical(aid) ?? throw Malformed(aid, $"The AID \"{aid}\" is not the canonical spelling of its key.");
            return IsUsableKey(raw) ? raw : throw Unusable(aid);
        }
    }
}

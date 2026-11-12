using System;
using System.Collections.Generic;
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

        // keripy's PreDex, the prefix derivation codes an AID may carry, with the raw size each
        // encodes (this.i @37rktct3). fiki reads none of them but B; it needs the table only to say
        // whether a keyid is a well-formed AID, which the KERI profile's R1 makes the verifier's job
        // before any key store is asked.
        private static readonly Dictionary<string, int> PrefixCodes = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            { "B", 32 }, { "D", 32 }, { "E", 32 }, { "F", 32 }, { "G", 32 }, { "H", 32 }, { "I", 32 },
            { "0D", 64 }, { "0E", 64 }, { "0F", 64 }, { "0G", 64 },
            { "1AAA", 33 }, { "1AAB", 33 }, { "1AAI", 33 }, { "1AAJ", 33 },
            { "1AAC", 57 }, { "1AAD", 57 },
            { "1AAE", 114 },
        };

        // The non-transferable codes other than B: secp256k1, Ed448 and secp256r1 keys, whose
        // algorithm the profile does not support.
        private static readonly HashSet<string> OtherNonTransferableCodes = new HashSet<string>(StringComparer.Ordinal) { "1AAA", "1AAC", "1AAI" };

        internal static bool OtherNonTransferable(string code) => OtherNonTransferableCodes.Contains(code);

        private const string UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        internal static string ToAid(byte[] raw) => Qb64(Code, raw);

        /// <summary>
        /// True when 32 bytes are a key fiki will verify with: the canonical encoding of a point on
        /// the curve that is not of small order. BouncyCastle 2.7.0's
        /// <c>Ed25519.ValidatePublicKeyPartial</c> refuses a y of 0, 1 or p - 1 or either order-8
        /// value (every encoding of the 8 small-order points, whatever the sign bit), any y at or
        /// above p, and a y with no x on the curve, which is the set to refuse. It does not refuse a
        /// point with a small-order component beside a large one, which OpenSSL accepts too, and
        /// which fiki's own raw keyid accepts (@5r75ff4m); <see cref="IsSubgroupKey"/> refuses it for
        /// a key an AID names. Against a small-order key a signature anyone can write verifies, so
        /// such a key is malformed, never attempted.
        /// </summary>
        internal static bool IsUsableKey(byte[] raw) => Ed25519.ValidatePublicKeyPartial(raw, 0);

        /// <summary>
        /// True when a usable key also lies in the prime-order subgroup, [L]P the identity, which is
        /// what libsodium's crypto_core_ed25519_is_valid_point accepts and keripy follows (KERI
        /// profile R1, this.i @37rktct3). BouncyCastle 2.7.0's <c>Ed25519.ValidatePublicKeyFull</c>
        /// makes exactly that check on top of the partial one: it decodes the point and multiplies it
        /// by L. Asked only after <see cref="IsUsableKey"/>, so what it adds is the mixed-order point,
        /// a subgroup point plus a torsion component.
        /// </summary>
        internal static bool IsSubgroupKey(byte[] raw) => Ed25519.ValidatePublicKeyFull(raw, 0);

        internal static FikiException Unusable(string keyId) => new FikiException(
            FikiErrorKind.MalformedKey,
            $"The key that {PyText.Shown(keyId)} names is not a usable Ed25519 public key: it is a point of small order, against which " +
            "anyone can forge a signature, or no canonical point on the curve at all.",
            keyId: keyId);

        /// <summary>
        /// The key an AID names, held to the prime-order subgroup: refused as small-order or
        /// off-curve first, as every key is, and then as mixed-order.
        /// </summary>
        internal static byte[] SubgroupKey(byte[] raw, string keyId)
        {
            if (!IsUsableKey(raw))
            {
                throw Unusable(keyId);
            }
            if (!IsSubgroupKey(raw))
            {
                throw new FikiException(
                    FikiErrorKind.MalformedKey,
                    $"The key that {PyText.Shown(keyId)} names is a point of mixed order, outside the prime-order subgroup every " +
                    "honest key lies in, so no signature is checked against it.",
                    keyId: keyId);
            }
            return raw;
        }

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
        internal static byte[]? Canonical(string qb64)
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
        /// The PreDex code of <paramref name="keyId"/> when it is a well-formed AID, else null (this.i
        /// @7w7nv94j, @37rktct3). The code is one, two or four characters by its first character, as
        /// CESR sizes it: a letter, then '0', then any other. The raw bytes behind it are padded with
        /// zero bytes in front to a multiple of three, base64url-encoded, and the code written over
        /// the characters the padding became. Well formed means exactly that spelling: the right
        /// length, base64url throughout, and zero pad bits, so that re-encoding gives back the keyid.
        /// fiki checks this before any resolver sees a keyid, so a resolver only ever answers about
        /// key state.
        /// </summary>
        internal static string? AidCode(string keyId)
        {
            var first = keyId.Length == 0 ? '\0' : keyId[0];
            var size = (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') ? 1 : first == '0' ? 2 : 4;
            if (keyId.Length < size || !PrefixCodes.TryGetValue(keyId.Substring(0, size), out var length))
            {
                return null;
            }
            var pad = (3 - length % 3) % 3;
            if (keyId.Length != (pad + length) * 4 / 3 + (size - pad))
            {
                return null;
            }
            var body = keyId.Substring(size);
            foreach (var c in body)
            {
                if (UrlAlphabet.IndexOf(c) < 0)
                {
                    return null;
                }
            }
            var decoded = Base64Url.Decode(new string('A', pad) + body);
            Array.Clear(decoded, 0, pad);
            return Base64Url.Encode(decoded).Substring(pad) == body ? keyId.Substring(0, size) : null;
        }

        /// <summary>True when <paramref name="keyId"/> is a well-formed AID under the KERI vectors' keys_rule.</summary>
        internal static bool WellFormed(string keyId) => AidCode(keyId) != null;

        private static FikiException Malformed(string aid, string message) =>
            new FikiException(FikiErrorKind.MalformedKey, message, keyId: aid);

        internal static byte[] VerifyingKey(string aid)
        {
            if (aid.Length != Qb64Length || aid[0] != Code)
            {
                throw new FikiException(
                    FikiErrorKind.MalformedKey,
                    $"A non-transferable AID is {Qb64Length} characters beginning with \"{Code}\"; this one " +
                    $"is {aid.Length} characters and begins with {PyText.Shown(aid.Length == 0 ? "" : aid.Substring(0, 1))}.",
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
                    throw Malformed(aid, $"The AID {PyText.Shown(aid)} is not valid base64url.");
                }
            }
            // "=" is in base64's alphabet, so a strict decoder accepts one or two of them at the end
            // and yields 32 or 31 bytes: short of a key, from a string of the right length and code.
            var padding = tail.Length - tail.TrimEnd('=').Length;
            if (tail.IndexOf('=') >= 0)
            {
                throw Malformed(aid, padding > 2 || tail.TrimEnd('=').IndexOf('=') >= 0
                    ? $"The AID {PyText.Shown(aid)} is not valid base64url."
                    : $"The AID {PyText.Shown(aid)} does not decode to a {RawLength}-byte key.");
            }
            var raw = Canonical(aid) ?? throw Malformed(aid, $"The AID {PyText.Shown(aid)} is not the canonical spelling of its key.");
            return IsUsableKey(raw) ? raw : throw Unusable(aid);
        }
    }
}

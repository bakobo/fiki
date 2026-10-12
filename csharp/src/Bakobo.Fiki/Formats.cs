using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Bakobo.Fiki
{
    /// <summary>
    /// Other spellings of an Ed25519 public key, read at the edge of the API (this.i @0mvgkwnl), for
    /// <see cref="Key.AidFrom"/>. A port of fiki-py's <c>formats.py</c>.
    /// </summary>
    /// <remarks>
    /// Nothing here touches a request. A verifier calls <see cref="Key.AidFrom"/> when it loads its
    /// registrations, so a bad one fails at configuration time rather than on a live request, and
    /// the expected AID stays a single spelling. Every spelling has exactly one accepted form, and
    /// every decoded key then goes through the same small-order refusal as a keyid (@37wdchu5), so
    /// no spelling is a way around it.
    /// </remarks>
    internal static class Formats
    {
        /// <summary>
        /// Checked before anything is decoded, so nothing below ever sees more than this. An OpenSSH
        /// public line's comment is the only part of any spelling that varies much, and 1024 UTF-16
        /// code units leaves it ample room.
        /// </summary>
        internal const int MaxPublicChars = 1024;

        private const int RawB64UrlLength = 43;
        private const string UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        // A base58btc value over 34 bytes is at most 47 characters after the "z"; anything longer
        // cannot be an Ed25519 did:key, and refusing it first keeps the arithmetic to a fixed size.
        private const int MaxMultibase = 48;

        private const string B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        // "ssh-ed25519", one space, the blob, and optionally one space and a printable-ASCII comment
        // that neither begins nor ends with a space, so that no whitespace around any field is ever
        // ignored. \A and \z rather than ^ and $, which would let a final newline through.
        private static readonly Regex SshLine = new Regex(
            @"\Assh-ed25519 ([A-Za-z0-9+/=]+)(?: [\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?)?\z",
            RegexOptions.CultureInvariant);

        /// <summary>
        /// Unpadded base64url, or null unless <paramref name="text"/> is the one canonical spelling of
        /// its bytes. Called only on 43 characters, a length base64url has, so the alphabet is the
        /// only shape left to check before the unused bits are.
        /// </summary>
        private static byte[]? B64Url(string text)
        {
            foreach (var c in text)
            {
                if (UrlAlphabet.IndexOf(c) < 0)
                {
                    return null;
                }
            }
            var data = Base64Url.Decode(text);
            return Base64Url.Encode(data) == text ? data : null;
        }

        /// <summary>
        /// base58btc, or null. Each leading "1" is one zero byte and the rest is the number's minimal
        /// big-endian bytes, so the decoding is a bijection: every string that decodes re-encodes to
        /// itself, and a leading "1" cannot add a zero byte without changing the bytes.
        /// </summary>
        private static byte[]? Base58(string text)
        {
            // The empty string decodes to no bytes, which the caller's length check refuses.
            // Big-endian, grown at the front as the number does.
            var number = new List<byte>();
            foreach (var c in text)
            {
                var carry = B58.IndexOf(c);
                if (carry < 0)
                {
                    return null;
                }
                for (var i = number.Count - 1; i >= 0; i--)
                {
                    carry += number[i] * 58;
                    number[i] = (byte)carry;
                    carry >>= 8;
                }
                for (; carry > 0; carry >>= 8)
                {
                    number.Insert(0, (byte)carry);
                }
            }
            // A "1" adds nothing to the number, so each leading one is written as a zero byte instead.
            number.InsertRange(0, new byte[text.Length - text.TrimStart('1').Length]);
            return number.ToArray();
        }

        /// <summary>
        /// The raw key under a did:key multibase value, which is base58btc ("z") only. The did:key
        /// ABNF also admits base64url ("u"), but its resolution algorithm requires "z" or raises
        /// invalidDid, and the peer DID ABNF has transform = "z"; reading "u" too would give every key
        /// two DIDs. The multicodec header must be exactly 0xed 0x01, so a non-minimal varint cannot
        /// name the same codec twice.
        /// </summary>
        private static byte[]? MultibaseEd25519(string value)
        {
            if (value.Length > MaxMultibase || !value.StartsWith("z", StringComparison.Ordinal))
            {
                return null;
            }
            var decoded = Base58(value.Substring(1));
            if (decoded == null || decoded.Length != 2 + Aids.RawLength || decoded[0] != 0xED || decoded[1] != 0x01)
            {
                return null;
            }
            var raw = new byte[Aids.RawLength];
            Array.Copy(decoded, 2, raw, 0, Aids.RawLength);
            return raw;
        }

        /// <summary>The raw key <paramref name="text"/> spells, by its shape, or null for a shape fiki does not read.</summary>
        private static byte[]? RawOf(string text)
        {
            // Length, not the first character, tells raw from AID: 43 against 44.
            if (text.Length == Aids.Qb64Length && text[0] == 'B')
            {
                return Aids.Canonical(text);
            }
            if (text.Length == RawB64UrlLength)
            {
                return B64Url(text);
            }
            if (text.StartsWith("did:key:", StringComparison.Ordinal))
            {
                return MultibaseEd25519(text.Substring("did:key:".Length));
            }
            if (text.StartsWith("did:peer:0", StringComparison.Ordinal))
            {
                return MultibaseEd25519(text.Substring("did:peer:0".Length));
            }
            var line = SshLine.Match(text);
            if (!line.Success)
            {
                return null;
            }
            var blob = OpenSsh.B64Std(line.Groups[1].Value);
            return blob == null ? null : OpenSsh.PublicBlob(blob);
        }

        private static FikiException Refuse(string message) => new FikiException(FikiErrorKind.MalformedKey, message, keyId: "");

        internal static string AidFrom(string text)
        {
            if (text.Length > MaxPublicChars)
            {
                throw Refuse($"A public key is at most {MaxPublicChars} characters in any spelling fiki reads; this one is {text.Length}.");
            }
            // Shape before meaning: only a canonically spelled D or E AID is told what it is.
            if (Aids.WellFormed(text) && text[0] != 'B')
            {
                throw Refuse(
                    "The text is a transferable or digest AID, whose current key is not recoverable from " +
                    "the identifier; resolve it to a key first.");
            }
            var raw = RawOf(text) ?? throw Refuse(
                $"The text, {text.Length} characters, is not an Ed25519 public key in any spelling fiki " +
                "reads: an AID, raw base64url, a base58btc did:key, a did:peer:0, or an ssh-ed25519 line.");
            if (!Aids.IsUsableKey(raw))
            {
                // The point check's refusal, without the keyid Aids.Unusable would quote.
                throw Refuse(
                    "The key given is a point of small order, under which a signature can be forged for any " +
                    "message, or not the canonical encoding of a point on the Ed25519 curve, so no signature " +
                    "is checked against it.");
            }
            return Aids.ToAid(raw);
        }
    }
}

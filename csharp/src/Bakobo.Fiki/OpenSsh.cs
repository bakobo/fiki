using System;
using Org.BouncyCastle.Crypto.Parameters;

namespace Bakobo.Fiki
{
    /// <summary>
    /// OpenSSH's encodings of an Ed25519 key (this.i @0mvgkwnl): the public blob an
    /// <c>ssh-ed25519</c> line carries, for <see cref="Formats"/>, and an unencrypted
    /// openssh-key-v1 private key, for <see cref="Key.FromOpenSsh"/>. A port of fiki-py's
    /// <c>openssh.py</c>.
    /// </summary>
    /// <remarks>
    /// Nothing here needs the small-order check: the seed a private key holds derives its own public
    /// key, a seed always derives a point of prime order, and the stored public key is checked
    /// against the derived one, so a weak stored key is refused as a mismatch.
    /// </remarks>
    internal static class OpenSsh
    {
        /// <summary>Checked before anything is decoded (input-handling standard: size, then shape, then meaning).</summary>
        internal const int MaxPrivateChars = 4096;

        private const string Begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
        private const string End = "-----END OPENSSH PRIVATE KEY-----";
        private const string StdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        private static readonly byte[] SshType = Ascii("ssh-ed25519");
        private static readonly byte[] Magic = Ascii("openssh-key-v1\0");
        private static readonly byte[] None = Ascii("none");

        private static byte[] Ascii(string text)
        {
            var bytes = new byte[text.Length];
            for (var i = 0; i < text.Length; i++)
            {
                bytes[i] = (byte)text[i];
            }
            return bytes;
        }

        internal static bool Same(byte[]? a, byte[] b)
        {
            if (a == null || a.Length != b.Length)
            {
                return false;
            }
            for (var i = 0; i < b.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Whether <paramref name="text"/> is shaped like standard base64: characters of its alphabet
        /// followed by at most two <c>=</c>, and nothing else, so no whitespace is ever skipped.
        /// </summary>
        private static bool StdShaped(string text)
        {
            var body = text.TrimEnd('=');
            if (text.Length - body.Length > 2)
            {
                return false;
            }
            foreach (var c in body)
            {
                if (StdAlphabet.IndexOf(c) < 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>Padded standard base64, or null unless <paramref name="text"/> is the one canonical spelling of its bytes.</summary>
        internal static byte[]? B64Std(string text)
        {
            if (!StdShaped(text) || text.Length % 4 != 0)
            {
                return null;
            }
            // Over the alphabet, a multiple of four long, and padded only at the end with at most
            // two "=": Convert cannot refuse it, but it ignores unused bits, so re-encoding is the check.
            var data = Convert.FromBase64String(text);
            return Convert.ToBase64String(data) == text ? data : null;
        }

        /// <summary>RFC 4251 section 5 wire fields, refusing any length that overruns what is there.</summary>
        private sealed class Reader
        {
            private readonly byte[] _data;
            private int _pos;

            internal Reader(byte[] data, int start)
            {
                _data = data;
                _pos = start;
            }

            internal uint? UInt32()
            {
                if (_data.Length - _pos < 4)
                {
                    return null;
                }
                var value = (uint)_data[_pos] << 24 | (uint)_data[_pos + 1] << 16 | (uint)_data[_pos + 2] << 8 | _data[_pos + 3];
                _pos += 4;
                return value;
            }

            internal byte[]? String()
            {
                var length = UInt32();
                if (length == null || length > (uint)(_data.Length - _pos))
                {
                    return null;
                }
                var value = new byte[length.Value];
                Array.Copy(_data, _pos, value, 0, value.Length);
                _pos += value.Length;
                return value;
            }

            internal byte[] Rest()
            {
                var rest = new byte[_data.Length - _pos];
                Array.Copy(_data, _pos, rest, 0, rest.Length);
                return rest;
            }
        }

        /// <summary>The 32 raw bytes of an ssh-ed25519 public blob with nothing after them, or null.</summary>
        internal static byte[]? PublicBlob(byte[] blob)
        {
            var reader = new Reader(blob, 0);
            if (!Same(reader.String(), SshType))
            {
                return null;
            }
            var raw = reader.String();
            return raw != null && raw.Length == Aids.RawLength && reader.Rest().Length == 0 ? raw : null;
        }

        // keyid is empty and the reason never quotes the input: a private key must not reach a log.
        private static FikiException Refuse(string reason) =>
            new FikiException(FikiErrorKind.MalformedKey, "The OpenSSH private key was refused: " + reason, keyId: "");

        /// <summary>
        /// The 32-byte Ed25519 seed in an unencrypted openssh-key-v1 private key: the armored key as
        /// ssh-keygen writes it, LF line endings, with or without the final newline. The key must be
        /// the only one in the file, its check integers must agree, its padding must be 1, 2, 3, ...,
        /// and its public key must match in both places it is stored and be the one its seed derives.
        /// </summary>
        internal static byte[] Read(string text)
        {
            if (text.Length > MaxPrivateChars)
            {
                throw Refuse($"it is over {MaxPrivateChars} characters.");
            }
            var lines = (text.EndsWith("\n", StringComparison.Ordinal) ? text.Substring(0, text.Length - 1) : text).Split('\n');
            if (lines.Length < 3 || lines[0] != Begin || lines[lines.Length - 1] != End)
            {
                throw Refuse($"it is not one \"{Begin}\" block with LF line endings and nothing around it.");
            }
            for (var i = 1; i < lines.Length - 1; i++)
            {
                if (lines[i].Length == 0 || !StdShaped(lines[i]))
                {
                    throw Refuse("its body is not lines of standard base64.");
                }
            }
            var blob = B64Std(string.Join("", lines, 1, lines.Length - 2))
                ?? throw Refuse("its body is not canonical standard base64.");
            if (!Same(Slice(blob, 0, Math.Min(blob.Length, Magic.Length)), Magic))
            {
                throw Refuse("it is not in the openssh-key-v1 format.");
            }
            var reader = new Reader(blob, Magic.Length);
            var cipher = reader.String();
            var kdf = reader.String();
            var kdfOptions = reader.String();
            if (cipher != null && !Same(cipher, None))
            {
                throw Refuse(
                    "it is encrypted under a passphrase, and fiki reads only unencrypted keys. Keep a " +
                    "dedicated key for fiki rather than removing the passphrase from one used elsewhere.");
            }
            if (cipher == null || !Same(kdf, None) || kdfOptions?.Length != 0 || reader.UInt32() != 1)
            {
                throw Refuse("its header is not that of exactly one unencrypted key.");
            }
            var publicBlob = reader.String();
            var raw = publicBlob == null ? null : PublicBlob(publicBlob);
            var privateSection = reader.String();
            if (raw == null || privateSection == null || reader.Rest().Length != 0)
            {
                throw Refuse("it is not exactly one ssh-ed25519 key with nothing after it.");
            }
            return PrivateSection(privateSection, raw);
        }

        private static byte[] Slice(byte[] data, int start, int length)
        {
            var slice = new byte[length];
            Array.Copy(data, start, slice, 0, length);
            return slice;
        }

        /// <summary>The seed from the private section, after every consistency check it carries.</summary>
        private static byte[] PrivateSection(byte[] section, byte[] raw)
        {
            var reader = new Reader(section, 0);
            var check = reader.UInt32();
            if (section.Length % 8 != 0 || check == null || check != reader.UInt32())
            {
                throw Refuse("its private section is misaligned or its check integers differ.");
            }
            var type = reader.String();
            var inner = reader.String();
            var secret = reader.String();
            var comment = reader.String();
            if (!Same(type, SshType) || !Same(inner, raw) || secret?.Length != 2 * Aids.RawLength)
            {
                throw Refuse("its private section does not hold the key its public section names.");
            }
            var seed = Slice(secret, 0, Aids.RawLength);
            var derived = new Ed25519PrivateKeyParameters(seed, 0).GeneratePublicKey().GetEncoded();
            if (!Same(Slice(secret, Aids.RawLength, Aids.RawLength), raw) || !Same(derived, raw))
            {
                throw Refuse("its seed does not derive the public key it is stored with.");
            }
            var padding = reader.Rest();
            if (comment == null || Array.Exists(comment, b => b < 0x20 || b > 0x7E))
            {
                throw Refuse("its comment is not printable ASCII.");
            }
            for (var i = 0; i < padding.Length; i++)
            {
                if (padding.Length >= 8 || padding[i] != i + 1)
                {
                    throw Refuse("its padding is not 1, 2, 3, ... to the next eight-byte boundary.");
                }
            }
            return seed;
        }
    }
}

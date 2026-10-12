using System;

namespace Bakobo.Fiki
{
    /// <summary>
    /// OpenSSH's encoding of an Ed25519 public key (this.i @0mvgkwnl): the blob an
    /// <c>ssh-ed25519</c> line carries, for <see cref="Formats"/>. A port of fiki-py's
    /// <c>openssh.py</c>.
    /// </summary>
    internal static class OpenSsh
    {
        private const string StdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        private static readonly byte[] SshType = Ascii("ssh-ed25519");

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
    }
}

using System;
using System.Text;

namespace Bakobo.Fiki.Tests
{
    /// <summary>Encoding helpers for the tests, written to the .NET Framework API floor.</summary>
    internal static class Bytes
    {
        public static byte[] FromHex(string hex)
        {
            var raw = new byte[hex.Length / 2];
            for (var i = 0; i < raw.Length; i++)
            {
                raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return raw;
        }

        public static string ToHex(byte[] raw)
        {
            var text = new StringBuilder(raw.Length * 2);
            foreach (var b in raw)
            {
                text.Append(b.ToString("x2"));
            }
            return text.ToString();
        }

        /// <summary>base64url, unpadded.</summary>
        public static string B64Url(byte[] raw) =>
            Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        /// <summary>Decode base64url with or without padding.</summary>
        public static byte[] FromB64Url(string text)
        {
            var standard = text.Replace('-', '+').Replace('_', '/');
            return Convert.FromBase64String(standard.PadRight(standard.Length + (4 - standard.Length % 4) % 4, '='));
        }

        public static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);

        public static string Text(byte[] raw) => Encoding.UTF8.GetString(raw);

        public static byte[] Range(int start, int count)
        {
            var raw = new byte[count];
            for (var i = 0; i < count; i++)
            {
                raw[i] = (byte)(start + i);
            }
            return raw;
        }
    }
}

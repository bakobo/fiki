using System;

namespace Bakobo.Fiki
{
    /// <summary>base64url without padding, to the netstandard2.0 API floor.</summary>
    internal static class Base64Url
    {
        internal static string Encode(byte[] raw) =>
            Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        /// <summary>Decode unpadded base64url the caller has already checked is over the alphabet.</summary>
        internal static byte[] Decode(string text)
        {
            var standard = text.Replace('-', '+').Replace('_', '/');
            return Convert.FromBase64String(standard + new string('=', (4 - standard.Length % 4) % 4));
        }
    }
}

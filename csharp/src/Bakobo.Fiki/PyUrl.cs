using System;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Bakobo.Fiki
{
    /// <summary>
    /// Python's <c>urllib.parse.urlsplit</c> (3.14), with <c>.hostname</c> and <c>.port</c>, which
    /// fiki-py derives @authority, @path and @query from. Reproduced rather than replaced by
    /// <see cref="Uri"/>, which normalizes paths and percent-encoding and so would build a different
    /// signature base from the same URL. Every refusal is an <see cref="ArgumentException"/>, the
    /// ValueError urlsplit raises.
    /// </summary>
    internal sealed class PyUrl
    {
        private const string SchemeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.";

        internal static readonly Regex IpvFuture = new Regex(@"\Av[a-fA-F0-9]+\..+\z", RegexOptions.CultureInvariant);

        private PyUrl(string scheme, string netloc, string path, string query)
        {
            Scheme = scheme;
            Netloc = netloc;
            Path = path;
            Query = query;
        }

        internal string Scheme { get; }

        internal string Netloc { get; }

        internal string Path { get; }

        internal string Query { get; }

        /// <summary>
        /// An origin-form request target (RFC 9112 section 3.2.1): everything before the first "?"
        /// is the path, verbatim, and there is no scheme and no authority (this.i @524c8qgv).
        /// </summary>
        internal static PyUrl OriginForm(string target)
        {
            var question = target.IndexOf('?');
            return question < 0
                ? new PyUrl("", "", target, "")
                : new PyUrl("", "", target.Substring(0, question), target.Substring(question + 1));
        }

        internal static PyUrl Split(string url)
        {
            // Only a leading C0 control or space is stripped, and TAB, CR and LF are removed anywhere.
            var start = 0;
            while (start < url.Length && url[start] <= ' ')
            {
                start++;
            }
            url = url.Substring(start).Replace("\t", "").Replace("\r", "").Replace("\n", "");

            var scheme = "";
            var colon = url.IndexOf(':');
            if (colon > 0 && IsAsciiLetter(url[0]) && AllSchemeChars(url.Substring(0, colon)))
            {
                scheme = url.Substring(0, colon).ToLowerInvariant();
                url = url.Substring(colon + 1);
            }

            var netloc = "";
            if (url.StartsWith("//", StringComparison.Ordinal))
            {
                var delimiter = url.Length;
                foreach (var c in "/?#")
                {
                    var at = url.IndexOf(c, 2);
                    if (at >= 0)
                    {
                        delimiter = Math.Min(delimiter, at);
                    }
                }
                netloc = url.Substring(2, delimiter - 2);
                url = url.Substring(delimiter);
                var open = netloc.IndexOf('[') >= 0;
                var close = netloc.IndexOf(']') >= 0;
                if (open != close)
                {
                    throw new ArgumentException("Invalid IPv6 URL");
                }
                if (open)
                {
                    CheckBracketedNetloc(netloc);
                }
            }

            var hash = url.IndexOf('#');
            if (hash >= 0)
            {
                url = url.Substring(0, hash);
            }
            var query = "";
            var question = url.IndexOf('?');
            if (question >= 0)
            {
                query = url.Substring(question + 1);
                url = url.Substring(0, question);
            }
            CheckNetloc(netloc);
            return new PyUrl(scheme, netloc, url, query);
        }

        private static bool IsAsciiLetter(char c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');

        private static bool AllSchemeChars(string text)
        {
            foreach (var c in text)
            {
                if (SchemeChars.IndexOf(c) < 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>Python's rpartition: the text after the last separator, or all of it.</summary>
        private static string AfterLast(string text, char separator) => text.Substring(text.LastIndexOf(separator) + 1);

        /// <summary>Python's partition: the text before the first separator, and the text after it (null when absent).</summary>
        private static string Before(string text, char separator, out string? after)
        {
            var at = text.IndexOf(separator);
            after = at < 0 ? null : text.Substring(at + 1);
            return at < 0 ? text : text.Substring(0, at);
        }

        private static void CheckBracketedNetloc(string netloc)
        {
            var hostAndPort = AfterLast(netloc, '@');
            var beforeBracket = Before(hostAndPort, '[', out var bracketed);
            string hostname;
            if (bracketed != null)
            {
                if (beforeBracket.Length > 0)
                {
                    throw new ArgumentException("Invalid IPv6 URL");
                }
                hostname = Before(bracketed, ']', out var port);
                if (!string.IsNullOrEmpty(port) && port![0] != ':')
                {
                    throw new ArgumentException("Invalid IPv6 URL");
                }
            }
            else
            {
                hostname = Before(hostAndPort, ':', out _);
            }

            if (hostname.StartsWith("v", StringComparison.Ordinal))
            {
                if (!IpvFuture.IsMatch(hostname))
                {
                    throw new ArgumentException("IPvFuture address is invalid");
                }
            }
            else if (!PyIp.IsIPv6(hostname))
            {
                // An IPv4 address in brackets is refused too, and is never a valid IPv6 one.
                throw new ArgumentException($"{PyText.Shown(hostname)} does not appear to be an IPv6 address");
            }
        }

        // Characters like U+2100 that expand under NFKC to "a/c" would smuggle a delimiter past the
        // split above, so urlsplit refuses them.
        private static void CheckNetloc(string netloc)
        {
            var ascii = true;
            foreach (var c in netloc)
            {
                ascii &= c <= '\x7f';
            }
            if (ascii)
            {
                return;
            }
            var n = netloc.Replace("@", "").Replace(":", "").Replace("#", "").Replace("?", "");
            var normalized = PyText.NormalizeKC(n);
            if (n != normalized && normalized.IndexOfAny("/?#@:".ToCharArray()) >= 0)
            {
                throw new ArgumentException($"netloc {PyText.Shown(netloc)} contains invalid characters under NFKC normalization");
            }
        }

        private string HostInfo(out string? port)
        {
            var hostInfo = AfterLast(Netloc, '@');
            Before(hostInfo, '[', out var bracketed);
            string hostname;
            if (bracketed != null)
            {
                hostname = Before(bracketed, ']', out var afterBracket);
                Before(afterBracket ?? "", ':', out port);
            }
            else
            {
                hostname = Before(hostInfo, ':', out port);
            }
            if (port == "")
            {
                port = null;
            }
            return hostname;
        }

        /// <summary>The host, lowercased except for an IPv6 zone, or null when there is none.</summary>
        internal string? Hostname
        {
            get
            {
                var hostname = HostInfo(out _);
                if (hostname.Length == 0)
                {
                    return null;
                }
                var host = Before(hostname, '%', out var zone);
                return PyText.Lower(host) + (zone == null ? "" : "%" + zone);
            }
        }

        /// <summary>The port, or null when the netloc names none.</summary>
        /// <exception cref="ArgumentException">The port is not a decimal number from 0 to 65535.</exception>
        internal int? Port
        {
            get
            {
                HostInfo(out var port);
                if (port == null)
                {
                    return null;
                }
                foreach (var c in port)
                {
                    if (c < '0' || c > '9')
                    {
                        throw new ArgumentException($"Port could not be cast to integer value as {PyText.Shown(port)}");
                    }
                }
                var trimmed = port.TrimStart('0');
                if (trimmed.Length > 5 || (trimmed.Length > 0 && int.Parse(trimmed, CultureInfo.InvariantCulture) > 65535))
                {
                    throw new ArgumentException("Port out of range 0-65535");
                }
                return trimmed.Length == 0 ? 0 : int.Parse(trimmed, CultureInfo.InvariantCulture);
            }
        }
    }

    /// <summary>Python's <c>ipaddress.IPv6Address</c> grammar, which urlsplit checks a bracketed host with.</summary>
    internal static class PyIp
    {
        private const int Hextets = 8;
        private const string HexDigits = "0123456789abcdefABCDEF";

        // ipaddress also refuses a "/", which never reaches here: urlsplit ends the netloc at one.
        internal static bool IsIPv6(string text)
        {
            var address = text;
            var percent = text.IndexOf('%');
            if (percent >= 0)
            {
                var scope = text.Substring(percent + 1);
                if (scope.Length == 0 || scope.IndexOf('%') >= 0)
                {
                    return false;
                }
                address = text.Substring(0, percent);
            }
            if (address.Length == 0 || address.Length > 45)
            {
                return false;
            }

            // At most nine parts are split off, so an address with too many colons keeps them in
            // its last part, which then fails as a hextet.
            var parts = new System.Collections.Generic.List<string>(SplitAtMost(address, ':', Hextets + 1));
            if (parts.Count < 3)
            {
                return false;
            }
            if (parts[parts.Count - 1].IndexOf('.') >= 0)
            {
                if (!IsIPv4(parts[parts.Count - 1]))
                {
                    return false;
                }
                // An IPv4 suffix stands for two hextets.
                parts[parts.Count - 1] = "0";
                parts.Add("0");
            }
            if (parts.Count > Hextets + 1)
            {
                return false;
            }

            var skip = -1;
            for (var i = 1; i < parts.Count - 1; i++)
            {
                if (parts[i].Length == 0)
                {
                    if (skip >= 0)
                    {
                        return false;
                    }
                    skip = i;
                }
            }

            int high;
            int low;
            if (skip >= 0)
            {
                high = skip;
                low = parts.Count - skip - 1;
                if (parts[0].Length == 0 && --high != 0)
                {
                    return false;
                }
                if (parts[parts.Count - 1].Length == 0 && --low != 0)
                {
                    return false;
                }
                if (Hextets - (high + low) < 1)
                {
                    return false;
                }
            }
            else
            {
                if (parts.Count != Hextets || parts[0].Length == 0 || parts[parts.Count - 1].Length == 0)
                {
                    return false;
                }
                high = parts.Count;
                low = 0;
            }

            for (var i = 0; i < high; i++)
            {
                if (!IsHextet(parts[i]))
                {
                    return false;
                }
            }
            for (var i = parts.Count - low; i < parts.Count; i++)
            {
                if (!IsHextet(parts[i]))
                {
                    return false;
                }
            }
            return true;
        }

        private static string[] SplitAtMost(string text, char separator, int maxSplits)
        {
            var parts = new System.Collections.Generic.List<string>();
            var start = 0;
            while (parts.Count < maxSplits)
            {
                var at = text.IndexOf(separator, start);
                if (at < 0)
                {
                    break;
                }
                parts.Add(text.Substring(start, at - start));
                start = at + 1;
            }
            parts.Add(text.Substring(start));
            return parts.ToArray();
        }

        private static bool IsHextet(string text)
        {
            foreach (var c in text)
            {
                if (HexDigits.IndexOf(c) < 0)
                {
                    return false;
                }
            }
            // Never empty: an empty part is the one "::" or an end it absorbs, and IsIPv6 parses
            // neither as a hextet.
            return text.Length <= 4;
        }

        private static bool IsIPv4(string text)
        {
            var octets = text.Split('.');
            if (octets.Length != 4)
            {
                return false;
            }
            foreach (var octet in octets)
            {
                if (octet.Length == 0 || octet.Length > 3 || (octet.Length > 1 && octet[0] == '0'))
                {
                    return false;
                }
                foreach (var c in octet)
                {
                    if (c < '0' || c > '9')
                    {
                        return false;
                    }
                }
                if (int.Parse(octet, CultureInfo.InvariantCulture) > 255)
                {
                    return false;
                }
            }
            return true;
        }
    }

    /// <summary>Text helpers shared by the ports' reading of untrusted values.</summary>
    internal static class PyText
    {
        /// <summary>
        /// Lowercase as Python does. Its full case mapping lowers U+0130 to two characters, "i" and a
        /// combining dot, where the invariant culture gives one.
        /// </summary>
        internal static string Lower(string text) => text.Replace("\u0130", "i\u0307").ToLowerInvariant();

        /// <summary>
        /// A-Z folded to a-z and nothing else, as fiki-py's <c>ascii_lower</c> folds field names
        /// (this.i @524c8qgv). Never <see cref="string.ToLowerInvariant"/>: .NET 10 folds U+212A
        /// KELVIN SIGN to an ASCII "k" and .NET Framework does not, and either way a field named with
        /// it would become a covered name it is not (review A6, B5).
        /// </summary>
        internal static string AsciiLower(string text)
        {
            var lowered = new StringBuilder(text.Length);
            foreach (var c in text)
            {
                lowered.Append(c >= 'A' && c <= 'Z' ? (char)(c + ('a' - 'A')) : c);
            }
            return lowered.ToString();
        }

        /// <summary>
        /// Python's <c>str.isprintable()</c> for the character at <paramref name="index"/>, a pair
        /// read as one code point: false for the categories Cc, Cf, Cs, Co, Cn, Zl and Zp, and for
        /// every Zs but the space, which is exactly what <c>repr()</c> escapes (tick 7us4). A lone
        /// surrogate is Cs. Unicode's tables are the runtime's, so a code point assigned after them
        /// reads as unassigned and is escaped, the safe direction.
        /// </summary>
        internal static bool IsPrintable(string text, int index)
        {
            if (text[index] == ' ')
            {
                return true;
            }
            switch (CharUnicodeInfo.GetUnicodeCategory(text, index))
            {
                case UnicodeCategory.Control:
                case UnicodeCategory.Format:
                case UnicodeCategory.Surrogate:
                case UnicodeCategory.PrivateUse:
                case UnicodeCategory.OtherNotAssigned:
                case UnicodeCategory.LineSeparator:
                case UnicodeCategory.ParagraphSeparator:
                case UnicodeCategory.SpaceSeparator:
                    return false;
                default:
                    return true;
            }
        }

        /// <summary>True when <paramref name="text"/> holds a surrogate that is not half of a pair, which has no UTF-8 encoding.</summary>
        internal static bool HasLoneSurrogate(string text)
        {
            for (var i = 0; i < text.Length; i++)
            {
                if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                {
                    i++;
                }
                else if (char.IsSurrogate(text[i]))
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// NFKC as Python's <c>unicodedata.normalize</c> computes it, which leaves a lone surrogate
        /// in place where <see cref="string.Normalize(NormalizationForm)"/> throws (tick 7us4). A
        /// surrogate code point decomposes to nothing and combines with nothing, so normalizing the
        /// runs between lone surrogates and keeping each surrogate is the same answer.
        /// </summary>
        internal static string NormalizeKC(string text)
        {
            var output = new StringBuilder();
            var start = 0;
            for (var i = 0; i < text.Length; i++)
            {
                if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                {
                    i++;
                }
                else if (char.IsSurrogate(text[i]))
                {
                    output.Append(text.Substring(start, i - start).Normalize(NormalizationForm.FormKC)).Append(text[i]);
                    start = i + 1;
                }
            }
            return output.Append(text.Substring(start).Normalize(NormalizationForm.FormKC)).ToString();
        }

        /// <summary>The longest stretch of an untrusted value an error message quotes (this.i @524c8qgv).</summary>
        internal const int ShownLength = 64;

        /// <summary>
        /// An untrusted value as an error message may quote it, as fiki-py's <c>shown</c> does: in
        /// quotes, with every character repr() escapes (<see cref="IsPrintable"/>), a quote and a
        /// backslash escaped, and cut at
        /// <see cref="ShownLength"/> characters with a note of how long it was, so a 5 MB URL cannot
        /// make a 10 MB message nor a control character reach a log raw (review A9, B9).
        /// </summary>
        internal static string Shown(string text)
        {
            // Total, so building a refusal's message never throws before the refusal (#18).
            if (text == null)
            {
                return "nothing";
            }
            var cut = text.Length > ShownLength;
            var length = cut ? ShownLength : text.Length;
            if (cut && char.IsHighSurrogate(text[length - 1]))
            {
                // Never split a pair, which would leave half a character in the message.
                length--;
            }
            var quoted = new StringBuilder("\"");
            for (var i = 0; i < length; i++)
            {
                var c = text[i];
                var pair = char.IsHighSurrogate(c) && i + 1 < length && char.IsLowSurrogate(text[i + 1]);
                var code = pair ? char.ConvertToUtf32(c, text[i + 1]) : c;
                if (!IsPrintable(text, i))
                {
                    // repr's spelling by width: \xhh, \uhhhh, or \Uhhhhhhhh past the BMP.
                    quoted.Append(code < 0x100 ? "\\x" : code < 0x10000 ? "\\u" : "\\U")
                        .Append(code.ToString(code < 0x100 ? "x2" : code < 0x10000 ? "x4" : "x8", CultureInfo.InvariantCulture));
                }
                else
                {
                    quoted.Append(c == '"' || c == '\\' ? "\\" : "").Append(text, i, pair ? 2 : 1);
                }
                i += pair ? 1 : 0;
            }
            var shown = quoted.Append('"').ToString();
            return cut ? shown + " (cut from " + text.Length.ToString(CultureInfo.InvariantCulture) + " characters)" : shown;
        }

        /// <summary>
        /// A name an error message mentions, such as a component identifier: left bare when it is at
        /// most <see cref="ShownLength"/> characters of printable ASCII, as a name a caller would
        /// recognize, and otherwise quoted and cut by <see cref="Shown"/> (this.i @524c8qgv).
        /// </summary>
        internal static string Named(string text)
        {
            if (text.Length > ShownLength)
            {
                return Shown(text);
            }
            foreach (var c in text)
            {
                if (c < ' ' || c > '~')
                {
                    return Shown(text);
                }
            }
            return text;
        }
    }
}

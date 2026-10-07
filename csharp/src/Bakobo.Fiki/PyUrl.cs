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

        private static readonly Regex IpvFuture = new Regex(@"\Av[a-fA-F0-9]+\..+\z", RegexOptions.CultureInvariant);

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
                throw new ArgumentException($"'{hostname}' does not appear to be an IPv6 address");
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
            var normalized = n.Normalize(NormalizationForm.FormKC);
            if (n != normalized && normalized.IndexOfAny("/?#@:".ToCharArray()) >= 0)
            {
                throw new ArgumentException($"netloc '{netloc}' contains invalid characters under NFKC normalization");
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
                        throw new ArgumentException($"Port could not be cast to integer value as '{port}'");
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

    /// <summary>Python's <c>str.strip()</c> and <c>str.lower()</c>, as fiki-py applies them to headers.</summary>
    internal static class PyText
    {
        // str.isspace(): bidirectional class WS, B or S, or category Zs. Listed rather than taken
        // from char.IsWhiteSpace, which omits U+001C..U+001F.
        private const string Space =
            "\t\n\v\f\r\u001c\u001d\u001e\u001f \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004" +
            "\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000";

        private static readonly char[] SpaceChars = Space.ToCharArray();

        internal static string Strip(string text) => text.Trim(SpaceChars);

        /// <summary>
        /// Lowercase as Python does. Its full case mapping lowers U+0130 to two characters, "i" and a
        /// combining dot, where the invariant culture gives one.
        /// </summary>
        internal static string Lower(string text) => text.Replace("\u0130", "i\u0307").ToLowerInvariant();
    }
}

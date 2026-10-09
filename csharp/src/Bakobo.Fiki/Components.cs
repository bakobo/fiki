using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Bakobo.Fiki
{
    /// <summary>
    /// The RFC 9421 signature base (section 2.5), as fiki-py's base.py builds it.
    /// </summary>
    /// <remarks>
    /// Derived components fiki builds: @method, @authority, @path and @query in a request, and
    /// @status in a response, which may also name its request's components with the <c>req</c>
    /// parameter of section 2.4 (@7f28p7xk). Anything else is refused rather than skipped: a
    /// component silently dropped from the base is one the caller believes is covered and is not.
    /// </remarks>
    internal static class Components
    {
        internal static readonly string[] Derived = { "@method", "@authority", "@path", "@query" };

        // The one derived component a response has of its own (RFC 9421 section 2.2.9).
        internal static readonly string[] ResponseDerived = { "@status" };

        internal const string ContentDigest = "content-digest";

        // The only component parameter fiki supports, and only in a response (section 2.4).
        internal const string ReqParam = "req";

        // RFC 9110 section 5.6.2's tchar: a token is one or more of them. A method is one (section
        // 9.1), and so is a field name (section 5.1), which fiki further requires lowercased.
        private const string TokenChars = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        // RFC 8941 section 3.3.1: an integer has at most fifteen digits.
        private const long MaxSfInteger = 999_999_999_999_999;

        private static readonly Dictionary<string, int> DefaultPorts = new Dictionary<string, int>
        {
            { "http", 80 }, { "https", 443 }, { "ws", 80 }, { "wss", 443 },
        };

        /// <summary>
        /// A component identifier from a caller's spelling of it: a plain name, or its RFC 8941
        /// serialization with parameters. Names are lowercased as a convenience to a local caller.
        /// </summary>
        /// <remarks>
        /// A field name that is not a token is the caller's mistake, an ArgumentException, because it
        /// would be serialized into Signature-Input as given (this.i @5zrf8gjk); a derived name fiki
        /// does not build is refused later, as UnsupportedComponent, which names it.
        /// </remarks>
        internal static SfItem Component(string spec)
        {
            var item = ComponentItem(spec);
            if (!item.Value.Text.StartsWith("@", StringComparison.Ordinal) && !IsToken(item.Value.Text))
            {
                throw new ArgumentException(
                    $"\"{spec}\" is not a component fiki can name: a field is named by an HTTP field name, one or more " +
                    "token characters, and a derived component by its @ name.");
            }
            return item;
        }

        internal static bool IsToken(string text)
        {
            if (text.Length == 0)
            {
                return false;
            }
            foreach (var c in text)
            {
                if (TokenChars.IndexOf(c) < 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// A request's method is an RFC 9110 token, covered or not, or the call is a mistake. Its case
        /// is kept as given (@22g0xkr8). Checked wherever a request message is built, on sign and
        /// verify alike (@5zrf8gjk): an empty or spaced method is never a request anybody sent.
        /// </summary>
        internal static void CheckMethod(string method)
        {
            if (method == null || !IsToken(method))
            {
                throw new ArgumentException(
                    $"The method \"{method}\" is not an HTTP method: a method is one or more token characters, with no " +
                    "spaces, line breaks or separators.",
                    nameof(method));
            }
        }

        /// <summary>
        /// What a signer serializes must be serializable, or the call is a mistake (@5zrf8gjk):
        /// created and expires are RFC 8941 integers that are not negative, and keyid, alg, nonce and
        /// tag are sf-strings, printable ASCII only, so a line break is refused by name before it
        /// could forge a header line. Checked before anything else about the message.
        /// </summary>
        internal static void CheckSignerParams(long? created, long? expires, string? keyId, string? alg, string? nonce, string? tag)
        {
            foreach (var (name, value) in new[] { ("created", created), ("expires", expires) })
            {
                if (value != null && (value < 0 || value > MaxSfInteger))
                {
                    throw new ArgumentException(
                        $"{name} is {value}, and RFC 8941 carries an integer of at most fifteen digits; fiki signs one from " +
                        $"0 to {MaxSfInteger}.",
                        name);
                }
            }
            foreach (var (name, value) in new[] { ("keyid", keyId), ("alg", alg), ("nonce", nonce), ("tag", tag) })
            {
                foreach (var c in value ?? "")
                {
                    if (c < ' ' || c > '~')
                    {
                        throw new ArgumentException(
                            $"The {name} \"{value}\" holds a character outside printable ASCII, which an RFC 8941 string " +
                            "cannot carry; a line break there would forge a header line.",
                            name);
                    }
                }
            }
        }

        private static SfItem ComponentItem(string spec)
        {
            if (spec.StartsWith("\"", StringComparison.Ordinal))
            {
                SfItem parsed;
                try
                {
                    parsed = Sfv.ParseItem(spec);
                }
                catch (FormatException)
                {
                    throw new FikiException(
                        FikiErrorKind.UnsupportedComponent,
                        $"fiki cannot read {spec} as a component identifier; name a component plainly, as \"@path\", " +
                        "or in its serialized form, as '\"@path\";req'.")
                    {
                        Component = spec,
                        Supported = string.Join(", ", Derived) + ", " + string.Join(", ", ResponseDerived),
                    };
                }
                var lowered = new SfItem(SfValue.OfString(PyText.AsciiLower(parsed.Value.Text)));
                foreach (var parameter in parsed.Params)
                {
                    lowered.Params.Set(parameter.Key, parameter.Value);
                }
                return lowered;
            }
            return new SfItem(SfValue.OfString(PyText.AsciiLower(spec)));
        }

        internal static string Req(string name)
        {
            var item = new SfItem(SfValue.OfString(PyText.AsciiLower(name)));
            item.Params.Set(ReqParam, SfValue.True);
            return item.Serialize();
        }

        /// <summary>The inverse of <see cref="Component"/>: a plain name when it has no parameters.</summary>
        internal static string SpecOf(SfItem item) => item.Params.Count > 0 ? item.Serialize() : item.Value.Text;

        internal static bool IsReq(SfItem item) => item.Params.TryGet(ReqParam, out var value) && value!.IsTrue;

        /// <summary>What two identifiers must share to be the same component. Parameter order is not it.</summary>
        internal static bool SameComponent(SfItem a, SfItem b) => string.Equals(Identity(a), Identity(b), StringComparison.Ordinal);

        /// <summary>
        /// py's <c>identity()</c> as one string, so a set can hold it: the value, then the parameters
        /// sorted by name, each value spelled so that two compare equal exactly when Python's
        /// <c>==</c> says they are (<see cref="SfValue.PyEquals"/>). Every part is length-prefixed,
        /// so no text can impersonate a separator.
        /// </summary>
        internal static string Identity(SfItem item)
        {
            var key = new StringBuilder(ValueKey(item.Value));
            var parameters = new List<KeyValuePair<string, SfValue>>(item.Params);
            parameters.Sort((x, y) => string.CompareOrdinal(x.Key, y.Key));
            foreach (var parameter in parameters)
            {
                key.Append(';').Append(Prefixed(parameter.Key)).Append('=').Append(ValueKey(parameter.Value));
            }
            return key.ToString();
        }

        private static string Prefixed(string text) => text.Length.ToString(CultureInfo.InvariantCulture) + ":" + text;

        private static string ValueKey(SfValue value)
        {
            switch (value.Type)
            {
                case SfType.Integer:
                case SfType.Decimal:
                case SfType.Boolean:
                    return "n" + Prefixed(Number(value));
                case SfType.String:
                case SfType.Token:
                    return "t" + Prefixed(value.Text);
                default:
                    return "b" + Prefixed(Convert.ToBase64String(value.Bytes));
            }
        }

        // A number's value with no trailing fractional zeros, so 1, 1.0 and true share a spelling.
        private static string Number(SfValue value)
        {
            var number = value.Type == SfType.Integer ? value.Integer : value.Type == SfType.Decimal ? value.Decimal : value.Boolean ? 1 : 0;
            if (number == 0)
            {
                // Zero, including a negative zero, which a runtime may print with its sign.
                return "0";
            }
            var text = number.ToString(CultureInfo.InvariantCulture);
            return text.IndexOf('.') >= 0 ? text.TrimEnd('0').TrimEnd('.') : text;
        }

        internal static bool Contains(IEnumerable<SfItem> items, SfItem wanted)
        {
            foreach (var item in items)
            {
                if (SameComponent(item, wanted))
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Refuse a covered list fiki cannot build faithfully: duplicates first, then the
        /// unsupported. That order is the KERI profile's section 9, so a list that is both has one
        /// correct refusal.
        /// </summary>
        internal static void CheckCovered(IList<SfItem> items, bool response)
        {
            // A set, as py's check_covered keeps one, so a long list costs linear work.
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in items)
            {
                if (!seen.Add(Identity(item)))
                {
                    throw new FikiException(
                        FikiErrorKind.DuplicateComponent,
                        $"The covered components name {SpecOf(item)} twice, so the signature base would not be " +
                        "what either copy says it is.")
                    { Component = SpecOf(item) };
                }
            }

            foreach (var item in items)
            {
                var isReq = IsReq(item);
                var other = false;
                foreach (var parameter in item.Params)
                {
                    other |= parameter.Key != ReqParam;
                }
                if (other || (item.Params.Contains(ReqParam) && !(isReq && response)))
                {
                    throw new FikiException(
                        FikiErrorKind.UnsupportedComponent,
                        $"fiki does not support the component {SpecOf(item)}: the only component parameter it supports " +
                        $"is \"{ReqParam}\", and only in a response.")
                    { Component = SpecOf(item), Supported = ReqParam };
                }
                if (item.Value.Text.StartsWith("@", StringComparison.Ordinal))
                {
                    var supported = isReq || !response ? Derived : ResponseDerived;
                    if (Array.IndexOf(supported, item.Value.Text) < 0)
                    {
                        throw new FikiException(
                            FikiErrorKind.UnsupportedComponent,
                            $"fiki does not build the derived component {SpecOf(item)} in a {(response ? "response" : "request")}; " +
                            $"it builds {string.Join(", ", supported)}.")
                        { Component = SpecOf(item), Supported = string.Join(", ", supported) };
                    }
                }
            }
        }

        /// <summary>A message the base is built from: a request, or a response and what it answers.</summary>
        internal sealed class Message
        {
            // A scheme, "://", and at least one character of authority (RFC 3986 section 3).
            private static readonly Regex AbsoluteTarget = new Regex(@"\A[A-Za-z][A-Za-z0-9+.-]*://[^/?#]", RegexOptions.CultureInvariant);

            private PyUrl? _parts;

            internal Message(Dictionary<string, string> headers, string? method, string? url, int? status, Message? request, bool received)
            {
                Headers = headers;
                Method = method;
                Url = url;
                Status = status;
                Request = request;
                Received = received;
            }

            internal Dictionary<string, string> Headers { get; }

            internal string? Method { get; }

            internal string? Url { get; }

            /// <summary>
            /// A message handed to a verifier rather than built by a signer, which decides what a URL
            /// that cannot be read is: a base that cannot be built when it arrived, a caller's mistake
            /// when signing (@5zrf8gjk).
            /// </summary>
            internal bool Received { get; }

            /// <summary>
            /// The URL, split only when a component needs it (@9g24rdns), so a request that covers
            /// neither @authority nor @path nor @query is never refused for a URL it never signed.
            /// </summary>
            internal PyUrl Parts => _parts ??= Split();

            /// <summary>
            /// The target as RFC 9112 section 3.2 reads it (this.i @524c8qgv). A target beginning
            /// with "/" is origin-form: everything before the first "?" is the path, verbatim, however
            /// many slashes it starts with, and its authority is the Host header's. urlsplit would read
            /// "//evil.example/p" as a network-path reference and let the sender choose the authority
            /// (review B1). Anything else must be a scheme, "://" and a non-empty authority. A space or
            /// an ASCII control anywhere is refused rather than stripped, since urlsplit's stripping
            /// made "/\nx" verify as "/x", and so is a fragment, which no request target has.
            /// </summary>
            private PyUrl Split()
            {
                var url = Url!;
                // Bounded before it is read, size before shape (this.i @524c8qgv).
                if (Encoding.UTF8.GetByteCount(url) > HttpSignatures.MaxFieldBytes)
                {
                    throw Unreadable($"it is over {HttpSignatures.MaxFieldBytes} bytes.");
                }
                foreach (var c in url)
                {
                    if (c <= ' ' || c == '\x7f')
                    {
                        throw Unreadable("it contains a space or a control character.");
                    }
                }
                if (url.IndexOf('#') >= 0)
                {
                    throw Unreadable("it carries a fragment, which no request target has.");
                }
                if (url.StartsWith("/", StringComparison.Ordinal))
                {
                    return PyUrl.OriginForm(url);
                }
                if (!AbsoluteTarget.IsMatch(url))
                {
                    throw Unreadable("it is neither origin-form, beginning with a slash, nor an absolute URI with a scheme and an authority.");
                }
                try
                {
                    return PyUrl.Split(url);
                }
                catch (ArgumentException ex)
                {
                    throw Unreadable(ex.Message + ".");
                }
            }

            /// <summary>
            /// A URL fiki cannot read. The profile's section 9 names a base that cannot be built a
            /// signature-mismatch, so a received URL whose port is not one is refused like any other
            /// base that does not verify, never raised from outside fiki's taxonomy.
            /// </summary>
            internal Exception Unreadable(string reason)
            {
                if (Received)
                {
                    return new FikiException(
                        FikiErrorKind.SignatureMismatch,
                        $"The URL {PyText.Shown(Url!)} cannot be read: {reason} So there is no signature base to check the signature against.");
                }
                return new ArgumentException($"The URL {PyText.Shown(Url!)} cannot be read: {reason}");
            }

            internal int? Status { get; }

            internal Message? Request { get; }
        }

        // Field names are case-insensitive and appear lowercased in the base (section 2.1), folded
        // A-Z only (this.i @524c8qgv). Values are kept as received, so their bound and their
        // characters are checked before the optional whitespace is trimmed. A later name wins, as in
        // a Python dict.
        private static Dictionary<string, string> Lowered(IEnumerable<KeyValuePair<string, string>> headers)
        {
            var lowered = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var header in headers)
            {
                lowered[PyText.AsciiLower(header.Key)] = header.Value;
            }
            return lowered;
        }

        /// <summary>
        /// A field value with leading and trailing SP and HTAB removed, and nothing else: RFC 9110
        /// section 5.5 makes only those optional whitespace (this.i @56qu7gyw). fiki-py's str.strip
        /// also removes CR, LF and Unicode whitespace, so "admin" followed by CR LF verified there as
        /// "admin"; here it stays in the value, and <see cref="ValueOf"/> refuses it as a mismatch.
        /// </summary>
        internal static string OwsTrimmed(string value) => value.Trim(' ', '\t');

        internal static Message RequestMessage(string method, string url, IEnumerable<KeyValuePair<string, string>> headers, bool received = false)
        {
            CheckMethod(method);
            return new Message(Lowered(headers), method, url, null, null, received);
        }

        internal static Message ResponseMessage(int status, IEnumerable<KeyValuePair<string, string>> headers, Request? request, bool received = false) =>
            new Message(Lowered(headers), null, null, status,
                request == null ? null : RequestMessage(request.Method, request.Url, request.Headers, received), received);

        /// <summary>
        /// The authority, normalized per section 2.2.3: lowercase host, default port omitted, and an
        /// IP-literal in its brackets. An origin-form target's authority is the Host header, which in
        /// HTTP/1.1 is the authority, and it passes every check an absolute URL's does, holds no
        /// userinfo and no list of hosts, and keeps its port, since without a scheme no port is a
        /// default one (this.i, "Host is validated like any authority").
        /// </summary>
        private static string Authority(Message message)
        {
            var parts = message.Parts;
            if (parts.Netloc.Length > 0)
            {
                if (parts.Netloc.IndexOf('@') >= 0)
                {
                    // RFC 9110 section 4.2.4: treat userinfo as an error, since it is used to obscure
                    // the authority (this.i @524c8qgv).
                    throw message.Unreadable("its authority carries user information.");
                }
                return HostPort(parts.Netloc, parts.Scheme, message);
            }
            if (!message.Headers.TryGetValue("host", out var host))
            {
                throw new FikiException(
                    FikiErrorKind.MissingComponent,
                    "The signature covers \"@authority\", but the URL carries no authority and the request has no Host " +
                    "header, so there is nothing to derive it from.")
                { Component = "@authority" };
            }
            // As any covered value is, as received and before it is lowercased (review B5).
            CheckRaw(host, "@authority", bounded: true);
            host = OwsTrimmed(host);
            if (host.IndexOf('@') >= 0 || host.IndexOf(',') >= 0)
            {
                throw message.Unreadable("its Host header is not a single host and optional port.");
            }
            return HostPort(host, "", message);
        }

        /// <summary>
        /// host[:port] normalized per RFC 9421 section 2.2.3, or a base that cannot be built. It is
        /// checked to be ASCII before anything is lowercased (review B5): .NET lowercases U+212A
        /// KELVIN SIGN to "k", which would turn a host no client sent into one this verifier serves.
        /// </summary>
        private static string HostPort(string hostport, string scheme, Message message)
        {
            foreach (var c in hostport)
            {
                if (c > '~')
                {
                    throw message.Unreadable("its authority holds a character outside ASCII.");
                }
            }
            string host;
            string portText;
            if (hostport.StartsWith("[", StringComparison.Ordinal))
            {
                var close = hostport.IndexOf(']');
                var rest = close < 0 ? "" : hostport.Substring(close + 1);
                if (close < 0 || !IsIPLiteral(hostport.Substring(1, close - 1)) || (rest.Length > 0 && rest[0] != ':'))
                {
                    throw message.Unreadable("its IP-literal is not an IPv6 address or IPvFuture in brackets followed by nothing but a port.");
                }
                host = hostport.Substring(0, close + 1);
                portText = rest.Length > 0 ? rest.Substring(1) : "";
            }
            else
            {
                var colon = hostport.IndexOf(':');
                host = colon < 0 ? hostport : hostport.Substring(0, colon);
                portText = colon < 0 ? "" : hostport.Substring(colon + 1);
                if (host.IndexOf('[') >= 0 || host.IndexOf(']') >= 0)
                {
                    throw message.Unreadable("a bracket belongs only around an IP-literal.");
                }
            }
            var port = Port(portText, message);
            host = PyText.AsciiLower(host);
            if (port == null || (DefaultPorts.TryGetValue(scheme, out var standard) && standard == port))
            {
                return host;
            }
            return host + ":" + port.Value.ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>RFC 3986 section 3.2.2: an IPv6 address, with an optional zone, or IPvFuture (@9g24rdns).</summary>
        private static bool IsIPLiteral(string text) =>
            text.StartsWith("v", StringComparison.Ordinal) ? PyUrl.IpvFuture.IsMatch(text) : PyIp.IsIPv6(text);

        /// <summary>
        /// RFC 3986 section 3.2.3: any run of ASCII digits, read as a number from 0 to 65535, so
        /// :000080 is port 80 and :08443 is 8443 (@5zrf8gjk). An empty port is no port at all.
        /// </summary>
        private static int? Port(string text, Message message)
        {
            if (text.Length == 0)
            {
                return null;
            }
            var plain = true;
            foreach (var c in text)
            {
                plain &= c >= '0' && c <= '9';
            }
            // Leading zeros go first, so no run longer than five digits is ever converted.
            var digits = text.TrimStart('0');
            if (!plain || digits.Length > 5 || (digits.Length > 0 && int.Parse(digits, NumberStyles.None, CultureInfo.InvariantCulture) > 65535))
            {
                throw message.Unreadable($"its port {PyText.Shown(text)} is not a number from 0 to 65535.");
            }
            return digits.Length == 0 ? 0 : int.Parse(digits, NumberStyles.None, CultureInfo.InvariantCulture);
        }

        private static string ComponentValue(SfItem item, Message message)
        {
            var name = item.Value.Text;
            if (IsReq(item))
            {
                message = message.Request ?? throw new FikiException(
                    FikiErrorKind.MissingComponent,
                    $"The signature covers {SpecOf(item)}, which is read from the request this response answers, and " +
                    "no request was supplied.")
                { Component = SpecOf(item) };
            }
            switch (name)
            {
                case "@status":
                    // Section 2.2.9: the three-digit status code, or there is no status line.
                    var status = message.Status!.Value;
                    if (status < 100 || status > 999)
                    {
                        throw new FikiException(
                            FikiErrorKind.MissingComponent,
                            $"The signature covers @status, and {status.ToString(CultureInfo.InvariantCulture)} is not a " +
                            "three-digit HTTP status code, so there is no status line to build.")
                        { Component = "@status" };
                    }
                    return status.ToString(CultureInfo.InvariantCulture);
                case "@method":
                    // Section 2.2.1: the method as sent, with no case transformation (@22g0xkr8).
                    // RequestMessage checked that it is a token (@5zrf8gjk).
                    return message.Method!;
                case "@authority":
                    return Authority(message);
                case "@path":
                    // An empty path is the "/" the origin server would have received.
                    var path = message.Parts.Path;
                    return path.Length == 0 ? "/" : path;
                case "@query":
                    // Section 2.2.7: the whole query string with its leading "?", percent-encoding
                    // preserved, and a bare "?" when the request carries no query at all.
                    return "?" + message.Parts.Query;
                default:
                    if (!message.Headers.TryGetValue(name, out var value))
                    {
                        throw new FikiException(
                            FikiErrorKind.MissingComponent,
                            $"The signature covers {SpecOf(item)}, but the message carries no value for it, so the " +
                            "signature base cannot be built.")
                        { Component = SpecOf(item) };
                    }
                    // Checked as received, before the optional whitespace is trimmed, so a value over
                    // the bound only before trimming is refused (this.i @524c8qgv).
                    CheckRaw(value, SpecOf(item), bounded: name != ContentDigest);
                    return OwsTrimmed(value);
            }
        }

        /// <summary>
        /// A component's value, refused when it has no single serialization both sides agree on: a
        /// line break would forge a line of the base, and a byte outside visible ASCII is encoded
        /// differently by different stacks. The KERI profile's draft 6 names such a base
        /// unbuildable, and so a signature-mismatch (@2f227n4r).
        /// </summary>
        internal static string ValueOf(SfItem item, Message message)
        {
            var value = ComponentValue(item, message);
            CheckRaw(value, SpecOf(item), bounded: item.Value.Text != ContentDigest);
            return value;
        }

        /// <summary>
        /// Refuse a value no signature base can be built from: over <see cref="HttpSignatures.MaxFieldBytes"/>
        /// UTF-8 bytes, checked first (size before shape, this.i @524c8qgv), or holding a line break,
        /// a control character or a non-ASCII character. Content-Digest is not bounded here: it has
        /// its own bound and its own kind, MalformedDigest, when it is parsed (@5zrf8gjk).
        /// </summary>
        private static void CheckRaw(string value, string spec, bool bounded)
        {
            if (bounded && Encoding.UTF8.GetByteCount(value) > HttpSignatures.MaxFieldBytes)
            {
                throw new FikiException(
                    FikiErrorKind.SignatureMismatch,
                    $"The value of {spec} is over {HttpSignatures.MaxFieldBytes} bytes, so no signature base is built from it.");
            }
            foreach (var c in value)
            {
                if (c != '\t' && (c < ' ' || c > '~'))
                {
                    throw new FikiException(
                        FikiErrorKind.SignatureMismatch,
                        $"The value of {spec} contains a line break, a control character or a non-ASCII " +
                        "character, so there is no signature base both sides would build from it.");
                }
            }
        }

        /// <summary>Every line of the signature base except the trailing @signature-params.</summary>
        internal static List<string> LinesFor(IEnumerable<SfItem> items, Message message)
        {
            var lines = new List<string>();
            foreach (var item in items)
            {
                var name = item.Serialize();
                lines.Add(name + ": " + ValueOf(item, message));
            }
            return lines;
        }

        internal static byte[] Join(List<string> lines, string signatureParams)
        {
            lines.Add("\"@signature-params\": " + signatureParams);
            return Encoding.UTF8.GetBytes(string.Join("\n", lines));
        }

        /// <summary>
        /// The @signature-params value fiki emits. Order is the signer's choice, since a verifier
        /// reserializes whatever it received, so fiki fixes one and keeps it (section 2.3).
        /// </summary>
        internal static string SignatureParams(IEnumerable<SfItem> items, long created, string keyId, string? alg, long? expires, string? nonce, string? tag)
        {
            var inner = new SfInnerList(items);
            inner.Params.Set("created", SfValue.OfInteger(created));
            if (expires != null)
            {
                inner.Params.Set("expires", SfValue.OfInteger(expires.Value));
            }
            if (nonce != null)
            {
                inner.Params.Set("nonce", SfValue.OfString(nonce));
            }
            if (alg != null)
            {
                inner.Params.Set("alg", SfValue.OfString(alg));
            }
            inner.Params.Set("keyid", SfValue.OfString(keyId));
            if (tag != null)
            {
                inner.Params.Set("tag", SfValue.OfString(tag));
            }
            return inner.Serialize();
        }

        internal static List<SfItem> Parse(IEnumerable<string> covered)
        {
            var items = new List<SfItem>();
            foreach (var spec in covered)
            {
                items.Add(Component(spec));
            }
            return items;
        }

        internal static byte[] RequestBase(string method, string url, IEnumerable<KeyValuePair<string, string>> headers,
            List<SfItem> items, long created, string keyId, string? alg, long? expires, string? nonce, string? tag)
        {
            CheckSignerParams(created, expires, keyId, alg, nonce, tag);
            var message = RequestMessage(method, url, headers);
            CheckCovered(items, response: false);
            var lines = LinesFor(items, message);
            return Join(lines, SignatureParams(items, created, keyId, alg, expires, nonce, tag));
        }

        internal static byte[] ResponseBase(int status, IEnumerable<KeyValuePair<string, string>> headers, Request? request,
            List<SfItem> items, long created, string keyId, string? alg, long? expires, string? nonce, string? tag)
        {
            CheckSignerParams(created, expires, keyId, alg, nonce, tag);
            var message = ResponseMessage(status, headers, request);
            CheckCovered(items, response: true);
            var lines = LinesFor(items, message);
            return Join(lines, SignatureParams(items, created, keyId, alg, expires, nonce, tag));
        }
    }
}

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

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

        private static readonly Dictionary<string, int> DefaultPorts = new Dictionary<string, int>
        {
            { "http", 80 }, { "https", 443 }, { "ws", 80 }, { "wss", 443 },
        };

        /// <summary>
        /// A component identifier from a caller's spelling of it: a plain name, or its RFC 8941
        /// serialization with parameters. Names are lowercased as a convenience to a local caller.
        /// </summary>
        internal static SfItem Component(string spec)
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
                var lowered = new SfItem(SfValue.OfString(PyText.Lower(parsed.Value.Text)));
                foreach (var parameter in parsed.Params)
                {
                    lowered.Params.Set(parameter.Key, parameter.Value);
                }
                return lowered;
            }
            return new SfItem(SfValue.OfString(PyText.Lower(spec)));
        }

        internal static string Req(string name)
        {
            var item = new SfItem(SfValue.OfString(PyText.Lower(name)));
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
            internal Message(Dictionary<string, string> headers, string? method, PyUrl? parts, int? status, Message? request)
            {
                Headers = headers;
                Method = method;
                Parts = parts;
                Status = status;
                Request = request;
            }

            internal Dictionary<string, string> Headers { get; }

            internal string? Method { get; }

            internal PyUrl? Parts { get; }

            internal int? Status { get; }

            internal Message? Request { get; }
        }

        // Field names are case-insensitive and appear lowercased in the base (section 2.1); values
        // are stripped of leading and trailing whitespace. A later name wins, as in a Python dict.
        private static Dictionary<string, string> Lowered(IEnumerable<KeyValuePair<string, string>> headers)
        {
            var lowered = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var header in headers)
            {
                lowered[PyText.Lower(header.Key)] = OwsTrimmed(header.Value);
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

        internal static Message RequestMessage(string method, string url, IEnumerable<KeyValuePair<string, string>> headers) =>
            new Message(Lowered(headers), method, PyUrl.Split(url), null, null);

        internal static Message ResponseMessage(int status, IEnumerable<KeyValuePair<string, string>> headers, Request? request) =>
            new Message(Lowered(headers), null, null, status,
                request == null ? null : RequestMessage(request.Method, request.Url, request.Headers));

        /// <summary>
        /// The authority, normalized per section 2.2.3: lowercase host, default port omitted, and an
        /// IPv6 literal in its brackets. A
        /// relative URL falls back to the Host header, which in HTTP/1.1 is the authority, and then
        /// nothing is normalized away, since without a scheme no port is a default port.
        /// </summary>
        private static string Authority(PyUrl parts, Dictionary<string, string> headers)
        {
            if (parts.Netloc.Length > 0)
            {
                var host = PyText.Lower(parts.Hostname ?? "");
                // An IPv6 literal keeps its brackets, lowercased inside them, as RFC 9421 section
                // 2.2.3 and RFC 3986 section 3.2.2 spell it. fiki-py drops them (tick 2h2g); this
                // port and the js port do not.
                if (parts.HostIsIPLiteral)
                {
                    host = "[" + host + "]";
                }
                var port = parts.Port;
                if (port == null || (DefaultPorts.TryGetValue(parts.Scheme, out var standard) && standard == port))
                {
                    return host;
                }
                return host + ":" + port.Value.ToString(CultureInfo.InvariantCulture);
            }
            if (!headers.TryGetValue("host", out var hostHeader))
            {
                throw new FikiException(
                    FikiErrorKind.MissingComponent,
                    "The signature covers \"@authority\", but the URL carries no authority and the request has no Host " +
                    "header, so there is nothing to derive it from.")
                { Component = "@authority" };
            }
            return PyText.Lower(hostHeader);
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
                    // Section 2.2.1: the method as sent, with no case transformation (@22g0xkr8). A
                    // request has a method, so an empty one is a caller who lost it, not an empty
                    // line to sign (this.i @56qu7gyw); refused only when @method is built.
                    if (string.IsNullOrEmpty(message.Method))
                    {
                        throw new ArgumentException("The signature covers @method, and the method given is empty; pass the method as it goes on the wire.");
                    }
                    return message.Method!;
                case "@authority":
                    return Authority(message.Parts!, message.Headers);
                case "@path":
                    // An empty path is the "/" the origin server would have received.
                    return message.Parts!.Path.Length == 0 ? "/" : message.Parts.Path;
                case "@query":
                    // Section 2.2.7: the whole query string with its leading "?", percent-encoding
                    // preserved, and a bare "?" when the request carries no query at all.
                    return "?" + message.Parts!.Query;
                default:
                    if (!message.Headers.TryGetValue(name, out var value))
                    {
                        throw new FikiException(
                            FikiErrorKind.MissingComponent,
                            $"The signature covers {SpecOf(item)}, but the message carries no value for it, so the " +
                            "signature base cannot be built.")
                        { Component = SpecOf(item) };
                    }
                    return value;
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
            foreach (var c in value)
            {
                if (c != '\t' && (c < ' ' || c > '~'))
                {
                    throw new FikiException(
                        FikiErrorKind.SignatureMismatch,
                        $"The value of {SpecOf(item)} contains a line break, a control character or a non-ASCII " +
                        "character, so there is no signature base both sides would build from it.");
                }
            }
            return value;
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
            CheckCovered(items, response: false);
            var lines = LinesFor(items, RequestMessage(method, url, headers));
            return Join(lines, SignatureParams(items, created, keyId, alg, expires, nonce, tag));
        }

        internal static byte[] ResponseBase(int status, IEnumerable<KeyValuePair<string, string>> headers, Request? request,
            List<SfItem> items, long created, string keyId, string? alg, long? expires, string? nonce, string? tag)
        {
            CheckCovered(items, response: true);
            var lines = LinesFor(items, ResponseMessage(status, headers, request));
            return Join(lines, SignatureParams(items, created, keyId, alg, expires, nonce, tag));
        }
    }
}

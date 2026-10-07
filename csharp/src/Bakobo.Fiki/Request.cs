using System.Collections.Generic;

namespace Bakobo.Fiki
{
    /// <summary>The request a response answers, which a response's <c>req</c> components are read from.</summary>
    public sealed class Request
    {
        private readonly byte[]? _body;

        /// <summary>A request: its method as sent, its URL, its headers, and its body when there is one.</summary>
        public Request(string method, string url, IEnumerable<KeyValuePair<string, string>>? headers = null, byte[]? body = null)
        {
            Method = method;
            Url = url;
            // Read once, here, and held read-only: HeaderSnapshot.Check validates these headers and
            // later steps read them again, which is sound only because nothing can change them.
            Headers = new List<KeyValuePair<string, string>>(headers ?? new KeyValuePair<string, string>[0]).AsReadOnly();
            _body = (byte[]?)body?.Clone();
        }

        /// <summary>The method, exactly as sent.</summary>
        public string Method { get; }

        /// <summary>The URL, absolute or the request target alone.</summary>
        public string Url { get; }

        /// <summary>The headers, in the order given.</summary>
        public IReadOnlyList<KeyValuePair<string, string>> Headers { get; }

        /// <summary>A copy of the body, or null when none was supplied.</summary>
        public byte[]? Body => (byte[]?)_body?.Clone();

        internal byte[]? BodyRef => _body;
    }
}

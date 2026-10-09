using System;
using System.Collections.Generic;

namespace Bakobo.Fiki
{
    /// <summary>
    /// A caller's headers, read exactly once at a public entry point, and every later step reads only
    /// this copy (bakobo/fiki#7).
    /// </summary>
    internal static class HeaderSnapshot
    {
        /// <summary>
        /// Copy the headers, refusing two field names equal case-insensitively (conductor ruling
        /// D-Q9ZT). Field names are case-insensitive, so such input holds two values for one field,
        /// and a list or map carries no received order to combine them by as RFC 9421 section 2.1
        /// would: lowering it would silently keep one, and a message signed over
        /// <c>x-role: member</c> would verify while also carrying <c>X-Role: admin</c>. Combining a
        /// repeated field into one value (RFC 9110 section 5.3) is the caller's to do before handing
        /// it over, so this is a caller's mistake, an ArgumentException, in every port since 0.8.0
        /// (this.i @5zrf8gjk).
        /// </summary>
        internal static IReadOnlyList<KeyValuePair<string, string>> Take(IEnumerable<KeyValuePair<string, string>> headers)
        {
            var snapshot = new List<KeyValuePair<string, string>>(headers);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var header in snapshot)
            {
                // A null name or value is no header anybody sent (@5zrf8gjk), and duplicates are found
                // by whether the name is already present, never by what a store returns.
                if (header.Key == null || header.Value == null)
                {
                    throw new ArgumentException(
                        $"A header is a name and a value, neither of them null; this one is {(header.Key == null ? "null" : PyText.Shown(header.Key))}: {(header.Value == null ? "null" : PyText.Shown(header.Value))}.",
                        nameof(headers));
                }
                var name = PyText.AsciiLower(header.Key);
                if (!seen.Add(name))
                {
                    throw new ArgumentException(
                        $"The headers name the field {PyText.Shown(name)} more than once, so it has two values and fiki cannot know " +
                        "which one was meant; combine them into one entry before signing or verifying.");
                }
            }
            return snapshot.AsReadOnly();
        }

        /// <summary>
        /// The same refusal for the headers of the request a response answers. One pass is enough,
        /// and the later steps may read <see cref="Request.Headers"/> again rather than this copy,
        /// because a Request reads its headers once when it is constructed and holds them in a
        /// read-only collection, so what is checked here is what is read there.
        /// </summary>
        internal static void Check(Request? request)
        {
            if (request != null)
            {
                Take(request.Headers);
            }
        }
    }
}

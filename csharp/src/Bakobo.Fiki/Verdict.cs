using System.Collections.Generic;

namespace Bakobo.Fiki
{
    /// <summary>
    /// The outcome of a successful verification; an exception means it did not verify. It asserts
    /// no freshness of its own: the caller supplied the message, and <c>created</c> is whatever the
    /// signer put there, so replay is the caller's problem.
    /// </summary>
    public sealed class Verdict
    {
        internal Verdict(string aid, IReadOnlyList<string> covered, string? keyId)
        {
            Aid = aid;
            Covered = covered;
            KeyId = keyId;
        }

        /// <summary>The non-transferable AID of the key that verified, or the keyid a resolver vouched for (@6g9zjsv9).</summary>
        public string Aid { get; }

        /// <summary>Each covered component as <see cref="HttpSignatures"/> would accept it back: a plain name, or its serialized form when it carries a parameter.</summary>
        public IReadOnlyList<string> Covered { get; }

        /// <summary>The keyid as received, or null when the signature carried none.</summary>
        public string? KeyId { get; }
    }
}

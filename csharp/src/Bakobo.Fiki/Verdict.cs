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

        /// <summary>
        /// The identity that vouched for the key: the non-transferable AID of a raw key, or the keyid
        /// a resolver vouched for (@6g9zjsv9), or the AID of the expected AID the verifier supplied.
        /// </summary>
        public string Aid { get; }

        /// <summary>Each covered component as <see cref="HttpSignatures"/> would accept it back: a plain name, or its serialized form when it carries a parameter.</summary>
        public IReadOnlyList<string> Covered { get; }

        /// <summary>
        /// The keyid exactly as it appeared on the wire, or null when the signature had none
        /// (this.i @5zrf8gjk), so a verifier given an expected AID can still see what the signer claimed.
        /// </summary>
        public string? KeyId { get; }
    }
}

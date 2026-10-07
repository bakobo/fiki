using System;
using System.Collections.Generic;

namespace Bakobo.Fiki
{
    /// <summary>
    /// How to verify a message. There is no constructor that leaves the freshness policy unstated:
    /// it is <see cref="MaxAge"/> or <see cref="DecliningFreshness"/>, because both defaults would be
    /// wrong (this.i @67shl6c5) — a value guesses at somebody else's clock skew and replay window, and
    /// skipping the check silently is the thing the choice exists to prevent. An <c>expires</c> the
    /// signer declared is enforced either way. Each <c>With</c> method returns a changed copy.
    /// </summary>
    public sealed class VerifyOptions
    {
        private VerifyOptions(long? maxAge)
        {
            MaxAgeSeconds = maxAge;
        }

        /// <summary>Refuse a signature whose <c>created</c> is more than <paramref name="seconds"/> old, beyond the skew allowance.</summary>
        public static VerifyOptions MaxAge(long seconds) => new VerifyOptions(seconds);

        /// <summary>Decline the age check, because replay protection lives elsewhere. A signer's own <c>expires</c> is enforced regardless.</summary>
        public static VerifyOptions DecliningFreshness() => new VerifyOptions(null);

        /// <summary>The maximum age in seconds, or null when the check was declined.</summary>
        public long? MaxAgeSeconds { get; }

        internal byte[]? Body { get; private set; }

        internal string? ExpectedAid { get; private set; }

        internal long Skew { get; private set; } = HttpSignatures.DefaultSkew;

        internal long? Now { get; private set; }

        internal Func<string, byte[]?>? Resolver { get; private set; }

        internal IReadOnlyList<string>? Minimum { get; private set; }

        internal string? ExpectedKeyId { get; private set; }

        internal ICollection<string>? Authorities { get; private set; }

        internal Request? Request { get; private set; }

        private VerifyOptions Copy() => (VerifyOptions)MemberwiseClone();

        /// <summary>
        /// The body received, which a covered content-digest is recomputed over. fiki cannot check a
        /// body it is not handed: a covered digest with no body is a DigestMismatch.
        /// </summary>
        public VerifyOptions WithBody(byte[]? body)
        {
            var copy = Copy();
            copy.Body = (byte[]?)body?.Clone();
            return copy;
        }

        /// <summary>
        /// The AID this message should be from: the preregistration case, authoritative over the
        /// keyid the message carries. Pass this or a resolver, not both.
        /// </summary>
        public VerifyOptions WithExpectedAid(string aid)
        {
            var copy = Copy();
            copy.ExpectedAid = aid;
            return copy;
        }

        /// <summary>Clock skew tolerated, in seconds; <see cref="HttpSignatures.DefaultSkew"/> unless changed.</summary>
        public VerifyOptions WithSkew(long seconds)
        {
            var copy = Copy();
            copy.Skew = seconds;
            return copy;
        }

        /// <summary>The clock reading to check freshness against, in seconds since the epoch. The real clock is read only when a check needs it.</summary>
        public VerifyOptions WithNow(long now)
        {
            var copy = Copy();
            copy.Now = now;
            return copy;
        }

        /// <summary>
        /// An authoritative lookup from a keyid, such as a transferable AID, to the 32-byte Ed25519
        /// key it names, returning null for a keyid it does not know (this.i @6g9zjsv9). fiki never
        /// falls back to decoding the keyid as a key. The resolver may throw a <see cref="FikiException"/>
        /// of its own, such as UnsupportedSigner, which is carried out unchanged.
        /// </summary>
        public VerifyOptions WithResolver(Func<string, byte[]?> resolve)
        {
            var copy = Copy();
            copy.Resolver = resolve;
            return copy;
        }

        /// <summary>
        /// The verifier's own covered-set policy: <see cref="HttpSignatures.RequestMinimum"/> or
        /// <see cref="HttpSignatures.ResponseMinimum"/>, or a superset (a smaller one is an
        /// ArgumentException). A signature covering less is refused even though it verifies, and so
        /// is a body without a covered content-digest. A minimum also makes <c>created</c> required.
        /// </summary>
        public VerifyOptions WithMinimum(IEnumerable<string> minimum)
        {
            var copy = Copy();
            copy.Minimum = new List<string>(minimum);
            return copy;
        }

        /// <summary>The keyid the signature must carry, such as the AID a client is talking to; any other is an UnknownKey.</summary>
        public VerifyOptions WithExpectedKeyId(string keyId)
        {
            var copy = Copy();
            copy.ExpectedKeyId = keyId;
            return copy;
        }

        /// <summary>The @authority values this verifier serves; a covered authority outside them is a SignatureMismatch. Requests only.</summary>
        public VerifyOptions WithAuthorities(IEnumerable<string> authorities)
        {
            var copy = Copy();
            copy.Authorities = new HashSet<string>(authorities, StringComparer.Ordinal);
            return copy;
        }

        /// <summary>The request a response answers, which its <c>req</c> components are read from. Responses only.</summary>
        public VerifyOptions WithRequest(Request request)
        {
            var copy = Copy();
            copy.Request = request;
            return copy;
        }
    }
}

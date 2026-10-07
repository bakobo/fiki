using System;

namespace Bakobo.Fiki
{
    /// <summary>
    /// Every error fiki reports about a message. Catch it to mean "this message was not usable",
    /// or discriminate on <see cref="Kind"/> when it matters which obstacle was hit.
    /// </summary>
    /// <remarks>
    /// The values an error is about — the offending component, label, keyid, algorithm, or
    /// timestamps — are carried as properties rather than only in the message, because a consumer
    /// translating fiki's errors into its own vocabulary (heti does, @4n9m4xfz) would otherwise make
    /// every reworded sentence a breaking change. A property is null when its kind does not carry it.
    /// </remarks>
    public class FikiException : Exception
    {
        /// <summary>
        /// Raise a fiki error. Public so that a key resolver can refuse a keyid in fiki's own terms,
        /// as <see cref="FikiErrorKind.UnsupportedSigner"/> or <see cref="FikiErrorKind.MalformedKey"/>.
        /// </summary>
        public FikiException(FikiErrorKind kind, string message, string? keyId = null)
            : base(message)
        {
            Kind = kind;
            KeyId = keyId;
        }

        /// <summary>The condition this error names.</summary>
        public FikiErrorKind Kind { get; }

        /// <summary>The label a signature header lacks (MissingSignatureLabel).</summary>
        public string? Label { get; internal set; }

        /// <summary>The keyid or AID at issue (MalformedKey, UnknownKey, UnsupportedSigner).</summary>
        public string? KeyId { get; internal set; }

        /// <summary>The component at issue, as <c>HttpSignatures</c> would accept it back (MissingComponent, UnsupportedComponent, DuplicateComponent, InsufficientCoverage).</summary>
        public string? Component { get; internal set; }

        /// <summary>What fiki does support instead (UnsupportedComponent).</summary>
        public string? Supported { get; internal set; }

        /// <summary>The algorithm the signature named (UnsupportedAlgorithm).</summary>
        public string? Alg { get; internal set; }

        /// <summary>The <c>expires</c> the signer declared (SignatureExpired).</summary>
        public long? Expires { get; internal set; }

        /// <summary>The <c>created</c> the signer declared, null when it declared none (SignatureTooOld).</summary>
        public long? Created { get; internal set; }

        /// <summary>The clock reading the freshness check used (SignatureExpired, SignatureTooOld).</summary>
        public long? Now { get; internal set; }

        /// <summary>The verifier's maximum age in seconds (SignatureTooOld).</summary>
        public long? MaxAge { get; internal set; }
    }
}

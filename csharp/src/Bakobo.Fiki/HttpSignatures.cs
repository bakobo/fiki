using System;
using System.Collections.Generic;

namespace Bakobo.Fiki
{
    /// <summary>
    /// Signing and verifying HTTP requests and responses per RFC 9421, with a bare Ed25519 key as
    /// the identifier.
    /// </summary>
    public static class HttpSignatures
    {
        /// <summary>
        /// The conformance contract this port satisfies (this.i @4fhrre0m): two artifacts interoperate
        /// when their declared vectors format matches, whatever their own version numbers say.
        /// </summary>
        public const int VectorsFormat = 1;

        /// <summary>
        /// The KERI profile's vector set this port satisfies, <c>vectors/keri/</c> (this.i
        /// @8vwrexxc). A separate number from <see cref="VectorsFormat"/>, because the two sets answer
        /// to different authorities and move independently.
        /// </summary>
        public const int KeriVectorsFormat = 2;

        /// <summary>The derived components fiki builds in a request.</summary>
        public static IReadOnlyList<string> Derived { get; } = Array.AsReadOnly(Components.Derived);

        /// <summary>
        /// The covered set a signature gets by default: @method, @authority, @path and @query, plus
        /// content-digest whenever there is a body (@2hwvpm42). <c>created</c> is a signature
        /// parameter rather than a component, so it is not listed though it is always covered.
        /// </summary>
        public static IReadOnlyList<string> DefaultCovered { get; } = Array.AsReadOnly(new[] { "@method", "@authority", "@path", "@query" });

        /// <summary>
        /// Build the RFC 9421 signature base for a request.
        /// </summary>
        /// <remarks>
        /// Public because when two implementations disagree about a signature, the base is where they
        /// disagree, and a caller debugging an interop failure needs to see the bytes. <paramref name="url"/>
        /// is a full URL or the request target alone, in which case @authority comes from the Host header.
        /// </remarks>
        /// <exception cref="FikiException">
        /// DuplicateComponent for a component named twice, UnsupportedComponent for a derived component
        /// outside <see cref="Derived"/> or a component parameter, MissingComponent for a covered field
        /// the request does not carry, and SignatureMismatch for a value with no single serialization.
        /// </exception>
        public static byte[] SignatureBase(
            string method,
            string url,
            IEnumerable<KeyValuePair<string, string>> headers,
            IEnumerable<string> covered,
            long created,
            string keyId,
            string? alg = null,
            long? expires = null,
            string? nonce = null,
            string? tag = null)
            => Components.RequestBase(method, url, headers, Components.Parse(covered), created, keyId, alg, expires, nonce, tag);

        /// <summary>
        /// Build the RFC 9421 signature base for a response (sections 2.2.9 and 2.4).
        /// <paramref name="request"/> is the request answered, which <c>req</c> components are read
        /// from; without one, a <c>req</c> component is a MissingComponent.
        /// </summary>
        public static byte[] ResponseSignatureBase(
            int status,
            IEnumerable<KeyValuePair<string, string>> headers,
            IEnumerable<string> covered,
            long created,
            string keyId,
            Request? request = null,
            string? alg = null,
            long? expires = null,
            string? nonce = null,
            string? tag = null)
            => Components.ResponseBase(status, headers, request, Components.Parse(covered), created, keyId, alg, expires, nonce, tag);

        /// <summary>The spelling of a request component named from a response: <c>Req("@path")</c> is <c>"@path";req</c>.</summary>
        public static string Req(string name) => Components.Req(name);
    }
}

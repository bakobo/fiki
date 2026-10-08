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
        public const int VectorsFormat = 2;

        /// <summary>
        /// The KERI profile's vector set this port satisfies, <c>vectors/keri/</c> (this.i
        /// @8vwrexxc). A separate number from <see cref="VectorsFormat"/>, because the two sets answer
        /// to different authorities and move independently.
        /// </summary>
        public const int KeriVectorsFormat = 4;

        /// <summary>
        /// The most bytes, UTF-8 and as received before any trimming, that fiki reads from each of
        /// Signature, Signature-Input and Content-Digest (this.i @5zrf8gjk). A longer field is that
        /// header's malformed kind, refused before it is parsed: size before shape.
        /// </summary>
        public const int MaxFieldBytes = 8192;

        /// <summary>The most members a Signature, Signature-Input or Content-Digest dictionary may hold.</summary>
        public const int MaxDictionaryMembers = 16;

        /// <summary>The most items an inner list in any of those headers may hold.</summary>
        public const int MaxInnerListItems = 64;

        /// <summary>The most parameters any item or inner list in those headers may carry.</summary>
        public const int MaxParameters = 16;

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
            => Components.RequestBase(method, url, HeaderSnapshot.Take(headers), Components.Parse(covered), created, keyId, alg, expires, nonce, tag);

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
            => Components.ResponseBase(status, HeaderSnapshot.Take(headers), Checked(request), Components.Parse(covered), created, keyId, alg, expires, nonce, tag);

        /// <summary>
        /// The KERI profile's minimum covered set for a request (section 3): @method, @path and
        /// @query, to which a body adds content-digest. Pass it, or a superset, as a minimum.
        /// </summary>
        public static IReadOnlyList<string> RequestMinimum { get; } = Array.AsReadOnly(Messages.RequestMinimum);

        /// <summary>
        /// The KERI profile's minimum covered set for a response (section 3): @status and the
        /// request's @method, @path and @query, each marked req. A body adds content-digest, and a
        /// request with content adds its "content-digest";req.
        /// </summary>
        public static IReadOnlyList<string> ResponseMinimum { get; } = Array.AsReadOnly(Messages.ResponseMinimum);

        /// <summary>Clock skew tolerated by default, in seconds: two hosts disagreeing by a second is ordinary.</summary>
        public const long DefaultSkew = 5;

        /// <summary>The RFC 9530 Content-Digest header value for a body: its sha-256.</summary>
        public static string ContentDigest(byte[] body) => Messages.ContentDigest(body);

        /// <summary>
        /// Sign a request, returning the headers to add to it: Signature-Input, Signature, and the
        /// Content-Digest fiki computed when there is one.
        /// </summary>
        /// <remarks>
        /// With a <paramref name="body"/> and no <paramref name="covered"/>, fiki digests the body and
        /// covers the digest; with an explicit covered set that omits content-digest, it refuses with
        /// UncoveredBody rather than sign a request whose body nothing binds (@2hwvpm42). A
        /// Content-Digest already among <paramref name="headers"/> is used rather than recomputed.
        /// <paramref name="method"/> is signed exactly as given (@22g0xkr8), so pass it as it will go on
        /// the wire. <paramref name="keyId"/> defaults to the key itself (@7xrx5evg); name another,
        /// such as a KERI AID, only when the verifier resolves it (@6g9zjsv9). A
        /// <paramref name="minimum"/> such as <see cref="RequestMinimum"/> makes the signer refuse a
        /// covered list its verifier would refuse. <paramref name="created"/> defaults to now.
        /// </remarks>
        /// <exception cref="FikiException">The message cannot be signed as asked.</exception>
        /// <exception cref="ArgumentException">A minimum below the profile's, or a value RFC 8941 cannot carry.</exception>
        public static IReadOnlyDictionary<string, string> SignRequest(
            Key key,
            string method,
            string url,
            IEnumerable<KeyValuePair<string, string>>? headers = null,
            byte[]? body = null,
            IEnumerable<string>? covered = null,
            long? created = null,
            string label = "sig",
            long? expires = null,
            string? nonce = null,
            string? tag = null,
            string? keyId = null,
            IEnumerable<string>? minimum = null)
            => Messages.SignRequest(key, method, url, headers, body, covered, created, label, expires, nonce, tag, keyId, minimum);

        /// <summary>
        /// Sign a response, returning the headers to add to it (RFC 9421 section 2.4).
        /// </summary>
        /// <remarks>
        /// By default the signature covers @status, a Content-Digest of any body, and, when the
        /// <paramref name="request"/> it answers is given, that request's method, path and query, plus
        /// its content-digest when it carried content, each marked req. A request whose content was
        /// non-empty and that has no Content-Digest to bind is refused as UncoveredBody, and a request
        /// digest its body contradicts is refused as the verifier would refuse it.
        /// </remarks>
        public static IReadOnlyDictionary<string, string> SignResponse(
            Key key,
            int status,
            Request? request = null,
            IEnumerable<KeyValuePair<string, string>>? headers = null,
            byte[]? body = null,
            IEnumerable<string>? covered = null,
            long? created = null,
            string label = "sig",
            long? expires = null,
            string? nonce = null,
            string? tag = null,
            string? keyId = null,
            IEnumerable<string>? minimum = null)
            => Messages.SignResponse(key, status, request, headers, body, covered, created, label, expires, nonce, tag, keyId, minimum);

        /// <summary>
        /// Verify a signed request, returning a <see cref="Verdict"/> or throwing.
        /// </summary>
        /// <remarks>
        /// <paramref name="url"/> is a full URL or the request target alone, in which case @authority
        /// comes from the Host header. Comparing the verdict's AID with the one you registered is the
        /// authorization step, and it is yours: fiki tells you who signed, never whether they may.
        /// </remarks>
        /// <exception cref="FikiException">The request did not verify; <see cref="FikiException.Kind"/> says why.</exception>
        /// <exception cref="ArgumentException">
        /// The call itself is wrong: both an expected AID and a resolver, a minimum below the profile's,
        /// options that apply only to responses, or a URL Python's urlsplit would refuse.
        /// </exception>
        public static Verdict VerifyRequest(string method, string url, IEnumerable<KeyValuePair<string, string>> headers, VerifyOptions options)
            => Messages.VerifyRequest(method, url, headers, options);

        /// <summary>
        /// Verify a signed response to the request in <see cref="VerifyOptions.WithRequest"/>,
        /// returning a <see cref="Verdict"/> or throwing.
        /// </summary>
        /// <remarks>
        /// An unsigned 401 is Unauthenticated, checked before anything else, because a server that
        /// refuses before it knows the agent cannot sign the refusal (@2f227n4r). A response's body is
        /// its content, never its Content-Length, so a HEAD or 304 response is bodiless whatever length
        /// it announces. A client should pass <see cref="VerifyOptions.WithExpectedKeyId"/>, the AID it
        /// is talking to (profile R1). A response covering "content-digest";req verified against a
        /// request with no body is an ArgumentException: fiki cannot check a body it was not given.
        /// </remarks>
        public static Verdict VerifyResponse(int status, IEnumerable<KeyValuePair<string, string>> headers, VerifyOptions options)
            => Messages.VerifyResponse(status, headers, options);

        private static Request? Checked(Request? request)
        {
            HeaderSnapshot.Check(request);
            return request;
        }

        /// <summary>The spelling of a request component named from a response: <c>Req("@path")</c> is <c>"@path";req</c>.</summary>
        public static string Req(string name) => Components.Req(name);
    }
}

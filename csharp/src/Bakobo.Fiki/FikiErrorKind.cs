namespace Bakobo.Fiki
{
    /// <summary>
    /// The condition a <see cref="FikiException"/> names (this.i @8zw78n0v).
    /// </summary>
    /// <remarks>
    /// Each name is the class name fiki-py raises for the same condition, and is a cross-language
    /// contract rather than an implementation detail: <c>vectors/refusals.json</c> records it for
    /// every refusal and every port asserts on it. The set is as fine-grained as heti's code taxonomy
    /// on purpose, so a sender can be told which header to fix rather than handed the pair.
    /// </remarks>
    public enum FikiErrorKind
    {
        // --- something the message needs is absent ---

        /// <summary>The message has no <c>Signature</c> header, so there is nothing to verify.</summary>
        MissingSignature,

        /// <summary>The message has no <c>Signature-Input</c> header, so no covered components are declared.</summary>
        MissingSignatureInput,

        /// <summary>The two signature headers name different labels, so neither describes the other.</summary>
        MissingSignatureLabel,

        /// <summary>A resolver was supplied and does not know the signature's keyid (this.i @6g9zjsv9).</summary>
        UnknownKey,

        /// <summary>The keyid's key state has no single key that satisfies its threshold alone. Raised by a resolver and carried out unchanged.</summary>
        UnsupportedSigner,

        /// <summary>The signature carries no keyid and the caller supplied no key.</summary>
        MissingKey,

        /// <summary>A covered component has no value in the message, so the base cannot be rebuilt.</summary>
        MissingComponent,

        /// <summary>An unsigned 401 answered the request, so the request was not authenticated and the refusal's body cannot be trusted.</summary>
        Unauthenticated,

        // --- something the message carries cannot be read ---

        /// <summary>The <c>Signature</c> header could not be parsed as an RFC 8941 dictionary.</summary>
        MalformedSignature,

        /// <summary>The <c>Signature-Input</c> header could not be parsed, or a member of it is not one fiki can read.</summary>
        MalformedSignatureInput,

        /// <summary>The signature headers carry other than exactly one label.</summary>
        MalformedSignatureLabel,

        /// <summary>The <c>Signature</c> value is not a 64-byte RFC 8941 byte sequence.</summary>
        MalformedSignatureValue,

        /// <summary>A key, keyid, or AID is not a well-formed 32-byte Ed25519 public key.</summary>
        MalformedKey,

        /// <summary>The <c>Content-Digest</c> header could not be parsed, or names no algorithm fiki computes.</summary>
        MalformedDigest,

        // --- fiki understood the message and will not handle it ---

        /// <summary>The covered set names a component or component parameter fiki does not build.</summary>
        UnsupportedComponent,

        /// <summary>The covered list names the same component twice, whatever the order of its parameters.</summary>
        DuplicateComponent,

        /// <summary>The signature verifies and covers less than the verifier's stated minimum (this.i @7f28p7xk).</summary>
        InsufficientCoverage,

        /// <summary>The signature names an algorithm fiki does not verify.</summary>
        UnsupportedAlgorithm,

        /// <summary>The message carries a body and the covered set does not include <c>content-digest</c>; raised when signing.</summary>
        UncoveredBody,

        // --- the message is well formed and signed, and a stated policy refuses it anyway ---

        /// <summary>The signature is past the <c>expires</c> its own signer declared.</summary>
        SignatureExpired,

        /// <summary>The signature's <c>created</c> is outside the verifier's maximum age, or in the future beyond the skew allowance.</summary>
        SignatureTooOld,

        // --- the message was read, and it does not hold up ---

        /// <summary>The received body does not hash to the covered <c>Content-Digest</c>.</summary>
        DigestMismatch,

        /// <summary>The signature does not verify over the message under the signer's key.</summary>
        SignatureMismatch,
    }
}

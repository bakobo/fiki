package com.bakobo.fiki;

/**
 * Every error fiki reports about a message it was asked to sign or verify.
 *
 * <p>The {@link Kind} names are a cross-language contract rather than an implementation detail:
 * {@code vectors/refusals.json} records the name fiki reports for each refusal, and every port
 * asserts on it. So a port that folds two conditions together fails a vector rather than passing
 * quietly, and heti — which maps these onto its own codes — can be told what happened by a client
 * in any language.
 *
 * <p>The granularity comes from heti's taxonomy, which distinguishes a missing header from an
 * unparsable one, per header, so a sender can be told which header to fix rather than handed the
 * pair.
 */
public class FikiException extends RuntimeException {

    /** The condition a refusal names. The enum constant name is what the shared vectors pin. */
    public enum Kind {
        // Something the request needs is absent.
        MissingSignature,
        MissingSignatureInput,
        MissingSignatureLabel,
        MissingKey,
        MissingComponent,
        // A resolver was supplied and does not know the keyid (@6g9zjsv9). Never answered by
        // decoding the keyid as a key instead.
        UnknownKey,
        // The keyid's key state has no single key that satisfies its threshold alone (@2f227n4r).
        // fiki never decides this itself; a resolver throws it and fiki carries it out unchanged.
        UnsupportedSigner,
        // An unsigned 401 answered the request: a server that refuses before it knows the agent
        // cannot sign the refusal, so the body of it is not to be trusted (@2f227n4r).
        Unauthenticated,

        // Something the request carries cannot be read.
        MalformedSignature,
        MalformedSignatureInput,
        MalformedSignatureLabel,
        MalformedSignatureValue,
        MalformedKey,
        MalformedDigest,

        // fiki understood the request and will not handle it.
        UnsupportedComponent,
        // The covered list names the same component twice, whatever the order of its parameters.
        DuplicateComponent,
        // The signature verifies, and covers less than the verifier's stated minimum (@7f28p7xk).
        InsufficientCoverage,
        UnsupportedAlgorithm,
        UncoveredBody,

        // The request is signed and a stated policy refuses it anyway (this.i @67shl6c5).
        SignatureExpired,
        SignatureTooOld,

        // The request was read, and it does not hold up.
        DigestMismatch,
        SignatureMismatch,
    }

    private final Kind kind;

    /**
     * The offending value, when there is one. Carried structurally rather than in the message, so
     * a consumer translating fiki's errors into its own vocabulary is not reading prose.
     */
    private final String detail;

    FikiException(Kind kind, String message) {
        this(kind, message, null);
    }

    /**
     * Public so that a caller's {@link Fiki.Resolver} can refuse a keyid in fiki's own terms —
     * {@code MalformedKey} for one that is not a well-formed identifier, {@code UnsupportedSigner}
     * for a key state with no single effective signer — which fiki carries out unchanged
     * (this.i @24tvlxgd).
     */
    public FikiException(Kind kind, String message, String detail) {
        super(message);
        this.kind = kind;
        this.detail = detail;
    }

    public Kind kind() {
        return kind;
    }

    public String detail() {
        return detail;
    }
}

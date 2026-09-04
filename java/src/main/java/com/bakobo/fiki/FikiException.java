package com.bakobo.fiki;

/**
 * Every error fiki reports about a request.
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

        // Something the request carries cannot be read.
        MalformedSignature,
        MalformedSignatureInput,
        MalformedSignatureLabel,
        MalformedSignatureValue,
        MalformedKey,
        MalformedDigest,

        // fiki understood the request and will not handle it.
        UnsupportedComponent,
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

    FikiException(Kind kind, String message, String detail) {
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

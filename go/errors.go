// Package fiki signs and verifies HTTP requests with a bare Ed25519 key as the identifier.
//
// Standard RFC 9421, with one lens: an Ed25519 public key is rendered as a non-transferable AID
// (CESR Ed25519N, a 44-character "B…" string), so the identifier is the verifying key and a
// verifier resolves nothing. See this.i @07wstqk7 in github.com/bakobo/fiki.
package fiki

import (
	"errors"
	"fmt"
)

// VectorsFormat is the conformance contract this port satisfies (this.i @4fhrre0m). Two artifacts
// interoperate when their declared vectors format matches, whatever their own version numbers say
// — so this is the number to compare, not the release. Monotonic, because a conformance contract
// has no meaningful minor: an implementation either satisfies the vectors or it does not.
//
// Go carries no version constant of its own: the module's version IS its tag, and duplicating it
// here would give it somewhere to go stale.
const VectorsFormat = 3

// KeriVectorsFormat is the KERI profile's conformance contract this port satisfies, the
// keri_vectors_format of vectors/keri/ (this.i @8vwrexxc, @9z57sejw). A separate number from
// VectorsFormat, because the two sets answer to different authorities and move independently.
const KeriVectorsFormat = 5

// ErrInvalidOptions marks a mistake in the call rather than a defect in the message: a minimum
// covered set smaller than the profile's, ExpectedAID together with Resolve, a message verified
// with no decision about MaxAge, a stated but empty ExpectedAID or ExpectedKeyid, a request
// verified with no decision about Authorities, a response verified with no decision about
// ExpectedKeyid, Authorities on a response, or a response binding "content-digest";req verified
// against a Request with no Body. Such an error wraps this one and is never an *Error, so a caller
// matching on Kind cannot take its own bug for a bad message (this.i @9z57sejw).
var ErrInvalidOptions = errors.New("fiki: invalid options")

func invalidOptions(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidOptions}, args...)...)
}

// Error is every error fiki returns about a request. The Kind names the condition, and the NAMES
// are a cross-language contract rather than an implementation detail: vectors/refusals.json
// records the name fiki reports for each refusal, and every port asserts on it. So a port that
// folds two conditions together fails a vector rather than passing quietly, and heti — which maps
// these onto its own codes — can be told what happened by a client in any language.
//
// The granularity comes from heti's taxonomy, which distinguishes a missing header from an
// unparsable one, per header, so a sender can be told which header to fix rather than handed the
// pair.
type Error struct {
	Kind    string
	Message string

	// The offending value, when there is one. Carried structurally rather than in the message,
	// so a consumer translating fiki's errors into its own vocabulary is not reading prose.
	Component string
	Supported string
	Label     string
	Keyid     string
	Alg       string
	Expires   int64
	Created   int64
	Now       int64
	MaxAge    int64
}

func (e *Error) Error() string { return e.Message }

// The kinds, one per condition the other ports name.
const (
	// Something the request needs is absent.
	KindMissingSignature      = "MissingSignature"
	KindMissingSignatureInput = "MissingSignatureInput"
	KindMissingSignatureLabel = "MissingSignatureLabel"
	KindMissingKey            = "MissingKey"
	KindMissingComponent      = "MissingComponent"
	KindUnauthenticated       = "Unauthenticated"

	// The keyid names no key the verifier knows, or not the one it expected (this.i @6g9zjsv9).
	// Never answered by decoding the keyid as a key instead: a basic transferable prefix embeds
	// its inception key, and reading it would accept a key that has been rotated away.
	KindUnknownKey = "UnknownKey"
	// The keyid's key state has no single key that satisfies its threshold alone (this.i
	// @2f227n4r). fiki never decides this itself; a Resolver returns it, and fiki passes it on.
	KindUnsupportedSigner = "UnsupportedSigner"

	// Something the request carries cannot be read.
	KindMalformedSignature      = "MalformedSignature"
	KindMalformedSignatureInput = "MalformedSignatureInput"
	KindMalformedSignatureLabel = "MalformedSignatureLabel"
	KindMalformedSignatureValue = "MalformedSignatureValue"
	KindMalformedKey            = "MalformedKey"
	KindMalformedDigest         = "MalformedDigest"

	// fiki understood the request and will not handle it.
	KindUnsupportedComponent = "UnsupportedComponent"
	KindDuplicateComponent   = "DuplicateComponent"
	KindUnsupportedAlgorithm = "UnsupportedAlgorithm"
	KindUncoveredBody        = "UncoveredBody"
	// The signature may be valid and covers less than the verifier's stated minimum (this.i
	// @7f28p7xk): a signature over too little is a signature over what an intermediary may change.
	KindInsufficientCoverage = "InsufficientCoverage"

	// The request is signed and a stated policy refuses it anyway (this.i @67shl6c5).
	KindSignatureExpired = "SignatureExpired"
	KindSignatureTooOld  = "SignatureTooOld"

	// The request was read, and it does not hold up.
	KindDigestMismatch    = "DigestMismatch"
	KindSignatureMismatch = "SignatureMismatch"
)

func errorf(kind, format string, args ...any) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

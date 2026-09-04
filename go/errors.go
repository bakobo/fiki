// Package fiki signs and verifies HTTP requests with a bare Ed25519 key as the identifier.
//
// Standard RFC 9421, with one lens: an Ed25519 public key is rendered as a non-transferable AID
// (CESR Ed25519N, a 44-character "B…" string), so the identifier is the verifying key and a
// verifier resolves nothing. See this.i @07wstqk7 in github.com/bakobo/fiki.
package fiki

import "fmt"

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

	// Something the request carries cannot be read.
	KindMalformedSignature      = "MalformedSignature"
	KindMalformedSignatureInput = "MalformedSignatureInput"
	KindMalformedSignatureLabel = "MalformedSignatureLabel"
	KindMalformedSignatureValue = "MalformedSignatureValue"
	KindMalformedKey            = "MalformedKey"
	KindMalformedDigest         = "MalformedDigest"

	// fiki understood the request and will not handle it.
	KindUnsupportedComponent = "UnsupportedComponent"
	KindUnsupportedAlgorithm = "UnsupportedAlgorithm"
	KindUncoveredBody        = "UncoveredBody"

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

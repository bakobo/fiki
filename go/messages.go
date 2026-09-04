package fiki

// Signing and verifying whole HTTP requests (`this.i` @2hwvpm42, @7xrx5evg, @67shl6c5).
//
// The keyid is always the signer's raw key and is not overridable, so "the request carries its own
// verifying key" holds for every fiki-signed request. A body is always covered or the signature is
// refused. And a verifier states a freshness policy or explicitly declines one.
//
// The bound worth stating plainly: fiki cannot cover a body it was never given. The guarantee is
// "hand fiki the body and it is covered, or fiki refuses" — a caller who omits it gets a valid
// signature over a request whose body nothing protects, and no library can detect that.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Alg is the only signature algorithm fiki produces or accepts.
const Alg = "ed25519"

// DefaultSkew tolerates two hosts disagreeing by a second, which is ordinary; a verifier that
// treats it as an attack is unusable.
const DefaultSkew int64 = 5

var digestAlgorithms = map[string]func([]byte) []byte{
	"sha-256": func(b []byte) []byte { s := sha256.Sum256(b); return s[:] },
	"sha-512": func(b []byte) []byte { s := sha512.Sum512(b); return s[:] },
}

const digestOut = "sha-256"

// ContentDigest is the RFC 9530 Content-Digest header value for a body.
func ContentDigest(body []byte) string {
	return digestOut + "=:" + base64.StdEncoding.EncodeToString(digestAlgorithms[digestOut](body)) + ":"
}

// SignOptions carries everything beyond the request itself.
type SignOptions struct {
	Body []byte
	// Covered is nil to take DefaultCovered. Naming your own is what turns a body without a
	// digest from a helpful addition into a refusal.
	Covered []string
	Created int64
	Label   string
	Expires int64
	Nonce   string
	Tag     string
}

// SignRequest signs a request and returns the headers to add to it.
func SignRequest(key *Key, method, rawURL string, headers map[string]string, opts SignOptions) (map[string]string, error) {
	supplied := headers
	if supplied == nil {
		supplied = map[string]string{}
	}
	sending := make(map[string]string, len(supplied)+1)
	for name, value := range supplied {
		sending[name] = value
	}

	// Whether the caller CHOSE the covered set is the difference between fiki helping and fiki
	// overriding. On the default path a body simply gets covered; on an explicit path, silently
	// adding a component would mean the signature covers something the caller did not ask for.
	chosen := opts.Covered != nil
	source := opts.Covered
	if !chosen {
		source = DefaultCovered
	}
	components := make([]string, len(source))
	for i, component := range source {
		components[i] = strings.ToLower(component)
	}

	if opts.Body != nil {
		if !slices.Contains(components, ContentDigestHeader) {
			if chosen {
				return nil, errorf(KindUncoveredBody,
					"This request carries a body, but the covered components do not include %q, so "+
						"the signature would not bind the body.", ContentDigestHeader)
			}
			components = append(components, ContentDigestHeader)
		}
		if !hasHeader(sending, ContentDigestHeader) {
			sending["Content-Digest"] = ContentDigest(opts.Body)
		}
	}

	created := opts.Created
	if created == 0 {
		created = time.Now().Unix()
	}
	label := opts.Label
	if label == "" {
		label = "sig"
	}

	base, err := SignatureBase(method, rawURL, sending, components, SignatureParams{
		Created: created, Keyid: key.Keyid(), Alg: Alg,
		Expires: opts.Expires, Nonce: opts.Nonce, Tag: opts.Tag,
	})
	if err != nil {
		return nil, err
	}
	signature := key.Sign(base)

	params := string(base)
	params = params[strings.LastIndex(params, `"@signature-params": `)+len(`"@signature-params": `):]
	out := map[string]string{
		"Signature-Input": label + "=" + params,
		"Signature":       label + "=:" + base64.StdEncoding.EncodeToString(signature) + ":",
	}
	if _, made := sending["Content-Digest"]; made && !hasHeader(supplied, ContentDigestHeader) {
		out["Content-Digest"] = sending["Content-Digest"]
	}
	return out, nil
}

func hasHeader(headers map[string]string, want string) bool {
	for name := range headers {
		if strings.ToLower(name) == want {
			return true
		}
	}
	return false
}

// Verdict is the outcome of a successful verification.
//
// It carries no timestamp and asserts no freshness beyond what was checked: the caller supplied
// the request, and `created` is whatever the signer put there.
type Verdict struct {
	AID     string
	Covered []string
}

// VerifyOptions carries the verifier's policy and the body it has in hand.
//
// MaxAge is a *int64 rather than an int64 because there is no default: seconds of tolerance, or
// an explicit nil to decline the check. Both defaults would be wrong (this.i @67shl6c5) — a value
// guesses at somebody else's clock skew and replay window, and skipping silently is the thing the
// field exists to prevent — so the caller states one either way.
type VerifyOptions struct {
	MaxAge      *int64
	Body        []byte
	ExpectedAID string
	Skew        *int64
	Now         int64
}

// VerifyRequest verifies a signed request.
func VerifyRequest(method, rawURL string, headers map[string]string, opts VerifyOptions) (*Verdict, error) {
	found := lowerHeaders(headers)

	list, signature, err := read(found)
	if err != nil {
		return nil, err
	}

	if alg, ok := list.param("alg"); ok {
		if text, _ := alg.(string); text != Alg {
			return nil, &Error{
				Kind:    KindUnsupportedAlgorithm,
				Message: fmt.Sprintf("This signature is made with %q, and fiki verifies only %s signatures.", text, Alg),
				Alg:     fmt.Sprint(alg),
			}
		}
	}

	aid, err := resolve(opts.ExpectedAID, list)
	if err != nil {
		return nil, err
	}
	public, err := VerifyingKey(aid)
	if err != nil {
		return nil, err
	}

	lines, err := componentLines(method, rawURL, headers, list.Items)
	if err != nil {
		return nil, err
	}
	lines = append(lines, `"@signature-params": `+serializeInnerList(list))
	base := []byte(strings.Join(lines, "\n"))

	if !ed25519.Verify(public, base, signature) {
		return nil, errorf(KindSignatureMismatch,
			"The signature does not match this request under the signer's key.")
	}

	// AFTER the signature check, deliberately. created and expires are covered by the signature,
	// so acting on them before verifying it would enforce a policy against values an attacker
	// could still have chosen — and would tell that attacker their forgery at least parsed.
	if err := checkFreshness(list, opts); err != nil {
		return nil, err
	}

	if slices.Contains(list.Items, ContentDigestHeader) {
		if err := checkDigest(found[ContentDigestHeader], opts.Body); err != nil {
			return nil, err
		}
	}
	return &Verdict{AID: aid, Covered: list.Items}, nil
}

func read(found map[string]string) (innerList, []byte, error) {
	var empty innerList
	rawInput, hasInput := found["signature-input"]
	rawSignature, hasSignature := found["signature"]
	if !hasInput || rawInput == "" {
		return empty, nil, errorf(KindMissingSignatureInput,
			"This request has no Signature-Input header, so there is no way to know which components a signature would cover.")
	}
	if !hasSignature || rawSignature == "" {
		return empty, nil, errorf(KindMissingSignature, "This request has no Signature header, so there is nothing to verify.")
	}

	inputOrder, inputs, err := parseDictionary(rawInput)
	if err != nil {
		return empty, nil, errorf(KindMalformedSignatureInput, "I could not parse the Signature-Input header.")
	}
	_, signatures, err := parseDictionary(rawSignature)
	if err != nil {
		return empty, nil, errorf(KindMalformedSignature, "I could not parse the Signature header.")
	}

	if len(inputOrder) != 1 {
		return empty, nil, errorf(KindMalformedSignatureLabel,
			"fiki verifies a request carrying exactly one signature; this one declares %d.", len(inputOrder))
	}
	label := inputOrder[0]
	entry, ok := signatures[label]
	if !ok || len(signatures) != 1 {
		return empty, nil, &Error{
			Kind:    KindMissingSignatureLabel,
			Message: "The Signature header carries no entry labelled " + label + ".",
			Label:   label,
		}
	}
	raw, ok := entry.Value.([]byte)
	if !ok {
		return empty, nil, errorf(KindMalformedSignatureValue,
			"RFC 9421 carries the signature as an RFC 8941 byte sequence, wrapped in colons.")
	}
	return inputs[label].List, raw, nil
}

func resolve(expectedAID string, list innerList) (string, error) {
	if expectedAID != "" {
		return expectedAID, nil
	}
	value, ok := list.param("keyid")
	keyid, _ := value.(string)
	if !ok || keyid == "" {
		return "", errorf(KindMissingKey,
			"This signature carries no keyid and no ExpectedAID was supplied, so there is no key to verify it against.")
	}
	raw, err := b64url.DecodeString(keyid)
	if err != nil || len(raw) != rawLen {
		return "", &Error{
			Kind:    KindMalformedKey,
			Message: "The keyid " + keyid + " is not a base64url-encoded 32-byte Ed25519 public key.",
			Keyid:   keyid,
		}
	}
	return ToAID(raw), nil
}

func checkFreshness(list innerList, opts VerifyOptions) error {
	expiresValue, hasExpires := list.param("expires")
	if !hasExpires && opts.MaxAge == nil {
		return nil
	}
	skew := DefaultSkew
	if opts.Skew != nil {
		skew = *opts.Skew
	}
	stamp := opts.Now
	if stamp == 0 {
		stamp = time.Now().Unix()
	}

	if hasExpires {
		expires, _ := expiresValue.(int64)
		if stamp > expires+skew {
			return &Error{
				Kind: KindSignatureExpired,
				Message: fmt.Sprintf("This signature expired at %d and it is now %d, so the signer has "+
					"already declared it should not be accepted.", expires, stamp),
				Expires: expires, Now: stamp,
			}
		}
	}
	if opts.MaxAge == nil {
		return nil
	}
	maxAge := *opts.MaxAge

	createdValue, hasCreated := list.param("created")
	if !hasCreated {
		return &Error{
			Kind: KindSignatureTooOld,
			Message: fmt.Sprintf("This signature carries no created timestamp, so its age cannot be "+
				"checked against the %d-second limit you asked for.", maxAge),
			Now: stamp, MaxAge: maxAge,
		}
	}
	created, _ := createdValue.(int64)
	if stamp-created > maxAge+skew {
		return &Error{
			Kind: KindSignatureTooOld,
			Message: fmt.Sprintf("This signature was created at %d, which is more than %d seconds "+
				"before %d, so it is too old to accept.", created, maxAge, stamp),
			Created: created, Now: stamp, MaxAge: maxAge,
		}
	}
	if created-stamp > skew {
		return &Error{
			Kind: KindSignatureTooOld,
			Message: fmt.Sprintf("This signature claims to have been created at %d, which is in the "+
				"future relative to %d by more than the %d-second skew allowance.", created, stamp, skew),
			Created: created, Now: stamp, MaxAge: maxAge,
		}
	}
	return nil
}

func checkDigest(header string, body []byte) error {
	// The header is covered by the signature, so it cannot have been tampered with — but a covered
	// digest still only attests to a body nobody hashed until somebody hashes it.
	if body == nil {
		return errorf(KindDigestMismatch,
			"The signature covers content-digest, but no body was supplied to check it against.")
	}
	order, parsed, err := parseDictionary(header)
	if err != nil {
		return errorf(KindMalformedDigest, "I could not parse the Content-Digest header.")
	}
	for _, name := range order {
		hash, known := digestAlgorithms[strings.ToLower(name)]
		if !known {
			continue
		}
		declared, ok := parsed[name].Value.([]byte)
		if !ok {
			return errorf(KindMalformedDigest, "A Content-Digest value is a byte sequence.")
		}
		if subtle.ConstantTimeCompare(hash(body), declared) != 1 {
			return errorf(KindDigestMismatch,
				"The request body does not match its %s Content-Digest, so the body is not the one that was signed.", name)
		}
		return nil
	}
	return errorf(KindMalformedDigest,
		"The Content-Digest header names no algorithm fiki computes; it computes sha-256 and sha-512.")
}

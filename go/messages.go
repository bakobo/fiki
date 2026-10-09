package fiki

// Signing and verifying whole HTTP requests and responses (`this.i` @2hwvpm42, @7xrx5evg,
// @67shl6c5, @7f28p7xk, @9z57sejw).
//
// The keyid is the signer's raw key unless the caller names another (@7xrx5evg, @6g9zjsv9), so
// "the request carries its own verifying key" holds for every fiki-signed request whose caller did
// not deliberately choose otherwise, and a verifier handed a Resolver never falls back to reading a
// key out of the keyid. A body is always covered or the signature is refused. And a verifier
// states a freshness policy or explicitly declines one.
//
// The bound worth stating plainly: fiki cannot cover a body it was never given. The guarantee is
// "hand fiki the body and it is covered, or fiki refuses" — a caller who omits it gets a valid
// signature over a message whose body nothing protects, and no library can detect that.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// Alg is the only signature algorithm fiki produces or accepts.
const Alg = "ed25519"

// DefaultSkew tolerates two hosts disagreeing by a second, which is ordinary; a verifier that
// treats it as an attack is unusable.
const DefaultSkew int64 = 5

// RequestMinimum and ResponseMinimum are the KERI profile's minimum covered sets (section 3), for
// a signer's or verifier's Minimum. A body adds content-digest on top, and a response to a request
// that had a body adds "content-digest";req.
var (
	RequestMinimum  = []string{"@method", "@path", "@query"}
	ResponseMinimum = []string{"@status", Req("@method"), Req("@path"), Req("@query")}
	// DefaultMinimum is what VerifyRequest requires when the caller states no Minimum of its own
	// (this.i @524c8qgv): fiki's own signing default, so a verifier left at its defaults accepts
	// what a fiki signer produces and nothing that covers less. Set NoMinimum to opt out.
	DefaultMinimum = []string{"@method", "@authority", "@path", "@query"}
)

// The values fiki itself reads. The exported slices above are for callers to read and pass; Go
// cannot make a slice immutable, and a policy any code in the process could rewrite is not a
// policy (#17 hostile pass), so verification and the profile floors use these private arrays.
var (
	requestMinimum  = [...]string{"@method", "@path", "@query"}
	responseMinimum = [...]string{"@status", `"@method";req`, `"@path";req`, `"@query";req`}
	defaultMinimum  = [...]string{"@method", "@authority", "@path", "@query"}
)

const (
	signatureLength = ed25519.SignatureSize
	keyLength       = ed25519.PublicKeySize
)

// RFC 9530. sha-256 on the way out; both are accepted on the way in, because fiki is not the only
// thing that will ever have signed a message it is asked to verify. Every one of these a header
// carries must match; any other algorithm is ignored (RFC 9530 section 2).
var digestAlgorithms = map[string]func([]byte) []byte{
	"sha-256": func(b []byte) []byte { s := sha256.Sum256(b); return s[:] },
	"sha-512": func(b []byte) []byte { s := sha512.Sum512(b); return s[:] },
}

const digestOut = "sha-256"

// RFC 9421 section 2.3's six signature parameters and whether each is an Integer (else a String).
// Anything else is refused rather than carried: a parameter fiki does not understand could be one
// whose meaning the signer relied on (@7f28p7xk).
var signatureParams = map[string]bool{"created": true, "expires": true, "nonce": false, "alg": false,
	"keyid": false, "tag": false}

// Resolver maps a keyid to the 32 raw bytes of the Ed25519 key it names (this.i @6g9zjsv9). It
// returns (nil, nil) when it knows no key for the keyid, which fiki reports as UnknownKey. Any error
// it returns, such as an *Error of kind UnsupportedSigner or MalformedKey, is passed on unchanged.
type Resolver func(keyid string) ([]byte, error)

// ContentDigest is the RFC 9530 Content-Digest header value for a body.
func ContentDigest(body []byte) string {
	return digestOut + "=:" + base64.StdEncoding.EncodeToString(digestAlgorithms[digestOut](body)) + ":"
}

// SignOptions carries everything beyond the message itself.
type SignOptions struct {
	// Body is the content to cover. Nil is no body; an empty non-nil one is a body of no bytes.
	Body []byte
	// Covered is nil to take the default. Naming your own is what turns a body without a digest
	// from a helpful addition into a refusal.
	Covered []string
	Created int64
	Label   string
	Expires int64
	Nonce   string
	Tag     string
	// Keyid is empty for the key itself, raw (@7xrx5evg). Name another, such as a KERI AID, only
	// when the verifier resolves it (@6g9zjsv9).
	Keyid string
	// Minimum, such as RequestMinimum, makes the signer refuse a covered list its verifier would
	// refuse. Nil applies none; one smaller than the profile's is ErrInvalidOptions.
	Minimum []string
}

// SignRequest signs a request and returns the headers to add to it.
//
// With a Body and no explicit Covered, fiki computes a Content-Digest, returns it among the
// headers, and covers it. With a Body and an explicit Covered that omits content-digest, fiki
// returns UncoveredBody rather than signing a request whose body nothing binds. method is signed
// exactly as given (@22g0xkr8), so pass it as it will go on the wire.
//
// Mistakes in the call are ErrInvalidOptions, never an *Error (this.i @5zrf8gjk): a method that is
// not an HTTP token, a URL whose authority cannot be read, such as one whose port is not a number
// from 0 to 65535, a label that is not an RFC 8941 key, a keyid, nonce or tag outside printable
// ASCII, a component name that is not a field name, a Created or Expires outside 0 to
// 999999999999999, and a supplied Content-Digest the Body does not match.
func SignRequest(key *Key, method, rawURL string, headers map[string]string, opts SignOptions) (map[string]string, error) {
	if err := checkLabel(opts.Label); err != nil {
		return nil, err
	}
	if err := floored(opts.Minimum, requestMinimum[:]); err != nil {
		return nil, err
	}
	sending, err := canonicalHeaders(headers)
	if err != nil {
		return nil, err
	}
	chosen := opts.Covered != nil
	source := opts.Covered
	if !chosen {
		source = DefaultCovered
	}
	items, err := parseComponents(source)
	if err != nil {
		return nil, err
	}
	generated := ""
	if items, generated, err = coverBody(items, sending, opts.Body, chosen); err != nil {
		return nil, err
	}
	if opts.Minimum != nil {
		hasBody := requestHasBody(sending, opts.Body)
		if err := checkMinimum(items, opts.Minimum, hasBody, false); err != nil {
			return nil, err
		}
	}
	m, err := canonicalMessage(method, rawURL, sending, false)
	if err != nil {
		return nil, err
	}
	base, err := buildBase(items, m, false, signerParams(key, opts))
	if err != nil {
		return nil, err
	}
	return signed(key, base, opts.Label, generated), nil
}

// SignResponse signs a response to request and returns the headers to add to it (RFC 9421
// section 2.4).
//
// By default the signature covers @status, a Content-Digest of any Body, and — when the request it
// answers is given — that request's method, path and query, plus its content-digest when its Body
// was non-empty, each marked req. That binds the response to what was asked. A request whose body
// was non-empty and which carries no Content-Digest to bind is refused as UncoveredBody rather than
// signed into a response every profile client refuses, and a request digest its Body contradicts
// is refused as the verifier would refuse it. The caller's mistakes are SignRequest's.
func SignResponse(key *Key, status int, request *Request, headers map[string]string, opts SignOptions) (map[string]string, error) {
	if err := checkLabel(opts.Label); err != nil {
		return nil, err
	}
	if err := floored(opts.Minimum, responseMinimum[:]); err != nil {
		return nil, err
	}
	sending, err := canonicalHeaders(headers)
	if err != nil {
		return nil, err
	}
	var requestHeaders map[string]string
	if request != nil {
		if requestHeaders, err = canonicalHeaders(request.Headers); err != nil {
			return nil, err
		}
	}
	chosen := opts.Covered != nil
	// By content alone: both sides hold the whole request by now (profile section 3, @7p9s3g9k).
	hadBody := request != nil && len(request.Body) > 0
	source := opts.Covered
	if !chosen {
		source = []string{"@status"}
		if request != nil {
			source = append(source, Req("@method"), Req("@path"), Req("@query"))
		}
	}
	items, err := parseComponents(source)
	if err != nil {
		return nil, err
	}
	generated := ""
	if items, generated, err = coverBody(items, sending, opts.Body, chosen); err != nil {
		return nil, err
	}
	if !chosen && hadBody {
		if _, ok := requestHeaders[ContentDigestHeader]; !ok {
			return nil, errorf(KindUncoveredBody,
				"The request this response answers carried a body and no Content-Digest, so the "+
					"response has nothing to bind that body with. Sign the request with a digest "+
					"first, or name the covered components yourself.")
		}
		items = append(items, componentID{Name: ContentDigestHeader, Params: []param{{Key: reqParam, Value: true}}})
	}
	if opts.Minimum != nil {
		if err := checkMinimum(items, opts.Minimum, len(opts.Body) > 0, hadBody); err != nil {
			return nil, err
		}
	}
	// The check VerifyResponse will make, made first: a signer does not vouch for a request
	// digest that the request body it was handed contradicts (bakobo/fiki#4).
	if request != nil && request.Body != nil && bindsRequestDigest(items) {
		header, present := requestHeaders[ContentDigestHeader]
		if err := checkDigest(header, present, request.Body); err != nil {
			return nil, err
		}
	}
	m := &message{headers: sending, status: status}
	if request != nil {
		if m.request, err = canonicalMessage(request.Method, request.URL, requestHeaders, false); err != nil {
			return nil, err
		}
	}
	base, err := buildBase(items, m, true, signerParams(key, opts))
	if err != nil {
		return nil, err
	}
	return signed(key, base, opts.Label, generated), nil
}

// checkDigest parses a Content-Digest and compares it with the body it describes.
func checkDigest(header string, present bool, body []byte) error {
	recognized, err := readDigest(header, present)
	if err != nil {
		return err
	}
	return compareDigest(recognized, body)
}

func signerParams(key *Key, opts SignOptions) SignatureParams {
	created := opts.Created
	if created == 0 {
		created = time.Now().Unix()
	}
	keyid := opts.Keyid
	if keyid == "" {
		keyid = key.Keyid()
	}
	return SignatureParams{Created: created, Keyid: keyid, Alg: Alg, Expires: opts.Expires,
		Nonce: opts.Nonce, Tag: opts.Tag}
}

// coverBody covers a body the caller handed over, or refuses to sign (@2hwvpm42). Whether the
// caller CHOSE the covered set is the difference between fiki helping and fiki overriding: on the
// default path a body simply gets covered, and on an explicit one, silently adding a component
// would mean the signature covers something the caller did not ask for.
func coverBody(items []componentID, sending map[string]string, body []byte, chosen bool) ([]componentID, string, error) {
	if body == nil {
		return items, "", nil
	}
	if !coversBody(items) {
		if chosen {
			return nil, "", errorf(KindUncoveredBody,
				"This message carries a body, but the covered components do not include %q, so "+
					"the signature would not bind the body. Add it to the covered set, or omit the "+
					"body if it is genuinely not part of what you are signing.", ContentDigestHeader)
		}
		items = append(items, componentID{Name: ContentDigestHeader})
	}
	if supplied, ok := sending[ContentDigestHeader]; ok {
		// A digest the caller supplied is checked, not trusted: signing one the body contradicts
		// would vouch for a body nobody sent (bakobo/fiki#6). One a verifier would not accept for
		// this body is the call's mistake, not a message's defect (this.i @5zrf8gjk).
		if err := checkDigest(supplied, true, body); err != nil {
			return nil, "", invalidOptions("The Content-Digest supplied with this body is not one a "+
				"verifier would accept for it: %s Omit it and fiki computes one, or supply the body "+
				"it describes.", err.Error())
		}
		return items, "", nil
	}
	sending[ContentDigestHeader] = ContentDigest(body)
	return items, sending[ContentDigestHeader], nil
}

func coversBody(items []componentID) bool {
	return slices.ContainsFunc(items, func(c componentID) bool {
		return c.Name == ContentDigestHeader && len(c.Params) == 0
	})
}

func bindsRequestDigest(items []componentID) bool {
	return slices.ContainsFunc(items, func(c componentID) bool {
		return c.Name == ContentDigestHeader && len(c.Params) == 1 && c.isReq()
	})
}

// labelled is the label a signature goes under: the caller's, or "sig" when none is named.
func labelled(label string) string {
	if label == "" {
		return "sig"
	}
	return label
}

// checkLabel refuses a label that is not an RFC 8941 key (section 3.1.2), as the caller's
// mistake: it is serialized into both headers as given (this.i @5zrf8gjk).
func checkLabel(label string) error {
	if !isSfKey(labelled(label)) {
		return invalidOptions("The label %s is not an RFC 8941 key: it starts with a lowercase letter "+
			"or '*' and continues with lowercase letters, digits, '_', '-', '.' and '*'.", shown(label))
	}
	return nil
}

// signed returns the signature headers, plus the Content-Digest fiki generated, if it did.
func signed(key *Key, base []byte, label, generated string) map[string]string {
	label = labelled(label)
	params := string(base)
	params = params[strings.LastIndex(params, `"@signature-params": `)+len(`"@signature-params": `):]
	out := map[string]string{
		"Signature-Input": label + "=" + params,
		"Signature":       label + "=:" + base64.StdEncoding.EncodeToString(key.Sign(base)) + ":",
	}
	if generated != "" {
		out["Content-Digest"] = generated
	}
	return out
}

// floored refuses a minimum smaller than the profile's. A supplied minimum selects the KERI
// profile's policy, so it may only add to the profile's own; anything smaller is the caller's
// mistake rather than a message's defect, and is reported before any message is read.
func floored(minimum, floor []string) error {
	if minimum == nil {
		return nil
	}
	given, err := parseComponents(minimum)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, item := range given {
		have[item.identity()] = true
	}
	var missing []string
	for _, spec := range floor {
		item, _ := parseComponent(spec) // the floors are fiki's own, well-formed specs
		if !have[item.identity()] {
			missing = append(missing, spec)
		}
	}
	if missing != nil {
		return invalidOptions("A minimum covered set must include the profile's own, %s; this one "+
			"leaves out %s.",
			strings.Join(floor, ", "), strings.Join(missing, ", "))
	}
	return nil
}

// requestHasBody is the profile's request body test: a length above zero, any transfer coding, or
// content. Requests only: a response's body is its content, since a HEAD or 304 response carries
// the length of a representation it does not send (@2f227n4r).
func requestHasBody(found map[string]string, body []byte) bool {
	if len(body) > 0 {
		return true
	}
	if _, chunked := found["transfer-encoding"]; chunked {
		return true
	}
	length, ok := found["content-length"]
	if !ok {
		return false
	}
	// Fail closed: a length that is not a plain decimal, negative ones included, is not evidence
	// that there is no body. A length is never parsed into an integer, so one of any number of
	// digits cannot overflow into "no body": any non-zero digit announces one (this.i @524c8qgv). Only SP and HTAB are optional whitespace (this.i @5zrf8gjk); a
	// no-break space or a vertical tab makes the value something other than a decimal.
	length = strings.Trim(length, " \t")
	return length == "" || strings.TrimLeft(length, "0123456789") != "" || strings.Trim(length, "0") != ""
}

func checkMinimum(items []componentID, minimum []string, hasBody, requestHadBody bool) error {
	have := map[string]bool{}
	for _, item := range items {
		have[item.identity()] = true
	}
	required, _ := parseComponents(minimum) // floored has already parsed every one
	if hasBody {
		required = append(required, componentID{Name: ContentDigestHeader})
	}
	if requestHadBody {
		required = append(required, componentID{Name: ContentDigestHeader, Params: []param{{Key: reqParam, Value: true}}})
	}
	for _, item := range required {
		if !have[item.identity()] {
			return &Error{
				Kind: KindInsufficientCoverage,
				Message: "The signature does not cover " + brief(item.spec()) + ", which this verifier " +
					"requires, so it is refused even though it may be valid: a signature over too " +
					"little is a signature over what an intermediary is free to change.",
				Component: item.spec(),
			}
		}
	}
	return nil
}

// Verdict is the outcome of a successful verification. An error means it did not verify.
//
// It carries no timestamp and asserts no freshness beyond what was checked: the caller supplied
// the message, and `created` is whatever the signer put there.
//
// AID is the identity that vouched for the key: the non-transferable AID of a raw key, the keyid a
// Resolver vouched for (@6g9zjsv9), or ExpectedAID. Keyid is the keyid exactly as it appeared on
// the wire, empty when the signature had none (this.i @5zrf8gjk), so a verifier given ExpectedAID
// can still see what the signer claimed. Covered names each component as a caller would spell it:
// a plain name, or its serialized form when it carries a parameter, such as `"@path";req`.
type Verdict struct {
	AID     string
	Covered []string
	Keyid   string
}

// VerifyOptions carries the verifier's policy and the body it has in hand.
//
// MaxAge is a *int64 rather than an int64 because there is no default: seconds of tolerance, or
// an explicit nil to decline the check. Both defaults would be wrong (this.i @67shl6c5) — a value
// guesses at somebody else's clock skew and replay window, and skipping silently is the thing the
// field exists to prevent — so the caller states one either way.
type VerifyOptions struct {
	MaxAge *int64
	// Body is the content received. Nil is none handed over.
	Body []byte
	// ExpectedAID is authoritative when given: the preregistration case, where the verifier
	// already knows whose message this should be and the inline key is only a claim. Resolve is
	// the other way to be authoritative. Give one or neither.
	ExpectedAID string
	Skew        *int64
	// Now pins the clock, in seconds since the epoch; zero reads the wall clock.
	Now     int64
	Resolve Resolver
	// Minimum is the verifier's covered-set policy, RequestMinimum or ResponseMinimum or a
	// superset of it: a signature covering less is refused even though it verifies, and so is a
	// body without a covered content-digest (@7f28p7xk). Any minimum also requires created, and a
	// keyid even beside ExpectedAID. Left nil, VerifyRequest applies DefaultMinimum and
	// VerifyResponse applies ResponseMinimum (@524c8qgv).
	Minimum []string
	// NoMinimum is the explicit opt-out from any minimum, the body rule included: a body handed
	// over with no covered content-digest is then accepted, and the verdict's Covered is the only
	// place that shows it (@2f227n4r). Setting it beside a Minimum is ErrInvalidOptions.
	NoMinimum bool
	// ExpectedKeyid refuses a signature by any other keyid as UnknownKey; a client passes the AID
	// it is talking to (profile R1). VerifyResponse requires a decision, like Authorities for a
	// request (this.i @524c8qgv): an ExpectedKeyid, or AnyKeyid to accept any signer and read it
	// from the verdict. Neither, both, or an empty ExpectedKeyid is ErrInvalidOptions there.
	// VerifyRequest checks no keyid unless given one, and refuses both.
	ExpectedKeyid string
	AnyKeyid      bool
	// Authorities and AnyAuthority are a decision VerifyRequest requires, like MaxAge, with no
	// default (@524c8qgv): state exactly one. Authorities is the non-empty set of @authority
	// values this verifier serves, each compared exactly with the one the request derives, so
	// "api.example.com:8443" and "api.example.com" are different hosts and an entry is written
	// lowercase with no default port. A covered @authority outside it is a SignatureMismatch,
	// because a request signed for one service must not replay to another (@2f227n4r), and
	// supplying it makes @authority required even under NoMinimum (@605z9tnw). AnyAuthority is
	// the explicit decision to check no authority. Neither, both, or an empty Authorities is
	// ErrInvalidOptions when a request is verified. Requests only: a response takes neither.
	Authorities  []string
	AnyAuthority bool
}

// VerifyRequest verifies a signed request.
//
// MaxAge and Skew, when given, are positive; zero or less is ErrInvalidOptions, as is a method that
// is not an HTTP token (this.i @5zrf8gjk). A URL whose authority cannot be read, such as one whose
// port is not a number from 0 to 65535, is a base that cannot be built, so a covered @authority
// makes it a SignatureMismatch. Signature, Signature-Input and Content-Digest are bounded before
// they are parsed, at MaxFieldBytes each, MaxDictionaryMembers members, MaxInnerListItems items in
// an inner list and MaxParameters parameters on an item, and a header over any of them is
// malformed.
func VerifyRequest(method, rawURL string, headers map[string]string, opts VerifyOptions) (*Verdict, error) {
	if err := checkWindow(opts); err != nil {
		return nil, err
	}
	if err := checkAuthorities(opts); err != nil {
		return nil, err
	}
	if opts.AnyKeyid && opts.ExpectedKeyid != "" {
		return nil, errBothKeyids
	}
	if err := checkNoMinimum(opts); err != nil {
		return nil, err
	}
	if opts.Minimum == nil && !opts.NoMinimum {
		opts.Minimum = defaultMinimum[:]
	}
	if err := floored(opts.Minimum, requestMinimum[:]); err != nil {
		return nil, err
	}
	m, err := requestMessage(method, rawURL, headers, true)
	if err != nil {
		return nil, err
	}
	return verify(m, false, nil, opts)
}

// VerifyResponse verifies a signed response to request.
//
// It fails closed as VerifyRequest does (this.i @524c8qgv): left without a Minimum it applies
// ResponseMinimum, whose req components are read from request, so a response verified under the
// default with no request is MissingComponent; NoMinimum opts out. ExpectedKeyid or AnyKeyid is
// a required decision. With ResponseMinimum, a request whose Body is non-empty obliges the response to cover
// "content-digest";req, and that digest is recomputed over request.Body, so verifying such a
// response against a Request with no Body is ErrInvalidOptions. A response's own body is its
// content, never its Content-Length. An unsigned 401 is Unauthenticated, checked before anything
// else in the message, because a server that refuses before it knows the agent cannot sign the
// refusal (@2f227n4r). The policy's limits and the input bounds are VerifyRequest's.
func VerifyResponse(status int, request *Request, headers map[string]string, opts VerifyOptions) (*Verdict, error) {
	if err := checkWindow(opts); err != nil {
		return nil, err
	}
	if err := checkExpectedKeyid(opts); err != nil {
		return nil, err
	}
	if err := checkNoMinimum(opts); err != nil {
		return nil, err
	}
	if opts.Minimum == nil && !opts.NoMinimum {
		opts.Minimum = responseMinimum[:]
	}
	if err := floored(opts.Minimum, responseMinimum[:]); err != nil {
		return nil, err
	}
	if opts.Authorities != nil || opts.AnyAuthority {
		return nil, invalidOptions("Authorities and AnyAuthority apply to a request a verifier " +
			"serves, not to a response; leave both unset.")
	}
	m, err := responseMessage(status, headers, request, true)
	if err != nil {
		return nil, err
	}
	// Empty counts as absent, as read treats it: an empty Signature header signs nothing. One of
	// only whitespace is present, and malformed, in every port (review B7).
	if status == 401 && m.headers["signature"] == "" {
		return nil, errorf(KindUnauthenticated,
			"The server answered 401 without signing the answer, so the request was not "+
				"authenticated and the body of the refusal cannot be trusted.")
	}
	return verify(m, true, request, opts)
}

// verify runs the KERI profile's section 9 order, so a message has exactly one correct refusal.
func verify(m *message, response bool, request *Request, opts VerifyOptions) (*Verdict, error) {
	if opts.ExpectedAID != "" && opts.Resolve != nil {
		return nil, invalidOptions("Pass ExpectedAID or Resolve, not both; each decides the key alone.")
	}
	found := m.headers
	list, signature, err := read(found, opts.ExpectedAID == "" || opts.Minimum != nil, opts.Minimum != nil)
	if err != nil {
		return nil, err
	}
	items := make([]componentID, len(list.Items))
	for i, member := range list.Items {
		items[i] = componentID{Name: member.Value.(string), Params: member.Params}
	}
	if err := checkCovered(items, response); err != nil {
		return nil, err
	}
	if opts.Minimum != nil {
		hasBody := len(opts.Body) > 0
		if !response {
			hasBody = requestHasBody(found, opts.Body)
		}
		// By the request's content alone, as SignResponse decides it (@7p9s3g9k).
		requestHadBody := request != nil && len(request.Body) > 0
		if err := checkMinimum(items, opts.Minimum, hasBody, requestHadBody); err != nil {
			return nil, err
		}
	}
	// Served authorities bind the signature to a host only if it commits to one, so supplying
	// them makes @authority required (@605z9tnw): coverage, before the key, as section 9 orders.
	if opts.Authorities != nil {
		if err := checkMinimum(items, []string{"@authority"}, false, false); err != nil {
			return nil, err
		}
	}

	// Section 9's key steps in order (this.i @5zrf8gjk): what the keyid alone shows, then the
	// expected keyid, and only then the resolver, which is never asked about a keyid already refused.
	value, _ := list.param("keyid")
	keyid, _ := value.(string)
	public, aid, err := localKey(opts.ExpectedAID, keyid, opts.Resolve)
	if err != nil {
		return nil, err
	}
	if opts.ExpectedKeyid != "" && keyid != opts.ExpectedKeyid {
		return nil, &Error{
			Kind:    KindUnknownKey,
			Message: fmt.Sprintf("This message is signed by %s, and the one expected is %s.", shown(keyid), shown(opts.ExpectedKeyid)),
			Keyid:   keyid,
		}
	}
	if public == nil {
		if public, aid, err = resolvedKey(keyid, opts.Resolve); err != nil {
			return nil, err
		}
	}
	if alg, ok := list.param("alg"); ok && alg != Alg {
		return nil, &Error{
			Kind:    KindUnsupportedAlgorithm,
			Message: fmt.Sprintf("This signature is made with %s, and fiki verifies only %s signatures.", shown(fmt.Sprint(alg)), Alg),
			Alg:     alg.(string),
		}
	}

	lines, err := componentLines(items, m)
	if err != nil {
		return nil, err
	}
	lines = append(lines, `"@signature-params": `+serializeInnerList(list))
	if !ed25519.Verify(public, []byte(strings.Join(lines, "\n")), signature) {
		return nil, errorf(KindSignatureMismatch,
			"The signature does not match this message under the signer's key, so the message "+
				"cannot be treated as authentic.")
	}

	if opts.Authorities != nil {
		for _, item := range items {
			if item.Name != "@authority" {
				continue
			}
			// Built once already, for the base, so it cannot fail here.
			served, _ := valueOf(item, m)
			if !slices.Contains(opts.Authorities, served) {
				return nil, errorf(KindSignatureMismatch,
					"The signature covers the authority %s, which this verifier does not serve, so "+
						"it was signed for somebody else.", shown(served))
			}
		}
	}

	// AFTER the signature check, deliberately. created and expires are covered by the signature,
	// so acting on them before verifying it would enforce a policy against values an attacker
	// could still have chosen — and would tell that attacker their forgery at least parsed.
	if err := checkFreshness(list, opts); err != nil {
		return nil, err
	}

	type owed struct {
		header  string
		present bool
		body    []byte
	}
	var digests []owed
	if coversBody(items) {
		header, present := found[ContentDigestHeader]
		digests = append(digests, owed{header, present, opts.Body})
	}
	// A response binding the request's digest binds a request body only if somebody hashes it
	// (bakobo/fiki#4). A verifier handed no request body cannot, and a verdict that skipped the
	// check would look like one that made it, so that is the caller's mistake, not a pass.
	if request != nil && bindsRequestDigest(items) {
		if request.Body == nil {
			return nil, invalidOptions(`The response covers "content-digest";req, so the request ` +
				"body it binds must be supplied in Request.Body to be checked; it was not.")
		}
		header, present := m.request.headers[ContentDigestHeader]
		digests = append(digests, owed{header, present, request.Body})
	}
	// Every covered digest is parsed before any is compared, so a malformed one outranks a
	// mismatched one wherever each sits (profile section 9).
	recognized := make([][]recognizedDigest, len(digests))
	for i, d := range digests {
		if recognized[i], err = readDigest(d.header, d.present); err != nil {
			return nil, err
		}
	}
	for i, d := range digests {
		if err := compareDigest(recognized[i], d.body); err != nil {
			return nil, err
		}
	}

	covered := make([]string, len(items))
	for i, item := range items {
		covered[i] = item.spec()
	}
	return &Verdict{AID: aid, Covered: covered, Keyid: keyid}, nil
}

// read pulls one signature and its input out of the headers, or says what is wrong with them, in
// the KERI profile's section 9 order: absence before malformation, the Signature header before
// Signature-Input, the members' shape before the label count.
func read(found map[string]string, requireKeyid, requireCreated bool) (innerList, []byte, error) {
	var empty innerList
	// Absent or empty only: a value of whitespace is present and fails to parse (review B7).
	if found["signature"] == "" {
		return empty, nil, errorf(KindMissingSignature, "This message has no Signature header, so there is nothing to verify.")
	}
	if found["signature-input"] == "" {
		return empty, nil, errorf(KindMissingSignatureInput,
			"This message has no Signature-Input header, so there is no way to know which "+
				"components a signature would cover.")
	}

	_, signatures, err := parseField(found["signature"], "Signature", KindMalformedSignature)
	if err != nil {
		return empty, nil, err
	}
	for _, entry := range signatures {
		if _, ok := entry.Value.([]byte); !ok {
			// Draft 6 of the KERI profile would call this malformed-signature, since such a header
			// is neither mode's form; the kind stays the one the shared vectors pin (@2f227n4r).
			return empty, nil, errorf(KindMalformedSignatureValue,
				"RFC 9421 carries a signature as an RFC 8941 byte sequence, wrapped in colons; this "+
					"Signature header carries something else.")
		}
	}
	inputOrder, inputs, err := parseField(found["signature-input"], "Signature-Input", KindMalformedSignatureInput)
	if err != nil {
		return empty, nil, err
	}
	for _, label := range inputOrder {
		if err := checkInput(inputs[label], requireKeyid, requireCreated); err != nil {
			return empty, nil, err
		}
	}

	if len(inputs) != 1 || len(signatures) != 1 {
		return empty, nil, errorf(KindMalformedSignatureLabel,
			"fiki verifies a message carrying exactly one signature; this one declares %d in "+
				"Signature-Input and %d in Signature.", len(inputs), len(signatures))
	}
	label := inputOrder[0]
	entry, ok := signatures[label]
	if !ok {
		return empty, nil, &Error{
			Kind: KindMissingSignatureLabel,
			Message: fmt.Sprintf("The Signature header carries no entry labelled %s, so the covered "+
				"components describe a signature that is not here.", shown(label)),
			Label: label,
		}
	}
	raw := entry.Value.([]byte)
	if len(raw) != signatureLength {
		return empty, nil, errorf(KindMalformedSignatureValue,
			"RFC 9421 carries an Ed25519 signature as a 64-byte RFC 8941 byte sequence, wrapped in "+
				"colons; this one is %d bytes.", len(raw))
	}
	return inputs[label].List, raw, nil
}

// parseField parses one of the three signature-related headers, bounded before it is read (this.i
// @5zrf8gjk): its size is measured as received, before anything is trimmed or parsed, and the
// counts are the parser's. Either refusal, like a parse failure, is the header's malformed kind.
func parseField(raw, name, kind string) ([]string, map[string]member, error) {
	if len(raw) > MaxFieldBytes {
		return nil, nil, errorf(kind, "The %s header is %d bytes, and fiki reads one of at most %d.",
			name, len(raw), MaxFieldBytes)
	}
	order, parsed, err := parseDictionary(raw)
	if err == nil && strings.Trim(raw, " \t") == "" {
		// Present, so not absent, and empty after OWS: a dictionary of nothing is malformed, as
		// every port must say alike (review B7).
		err = errSyntax
	}
	if err != nil {
		return nil, nil, errorf(kind, "I could not parse the %s header as an RFC 8941 dictionary: %v.", name, err)
	}
	return order, parsed, nil
}

// checkInput refuses a Signature-Input member fiki would otherwise have to guess about.
func checkInput(entry member, requireKeyid, requireCreated bool) error {
	if !entry.IsList {
		return errorf(KindMalformedSignatureInput,
			"A Signature-Input member is a parenthesized list of covered components; this one is a single value.")
	}
	for _, component := range entry.List.Items {
		name, ok := component.Value.(string)
		if !ok {
			return errorf(KindMalformedSignatureInput,
				"Every covered component is named by a quoted string; %s is not one.", brief(serializeBareItem(component.Value)))
		}
		if !strings.HasPrefix(name, "@") && name != strings.ToLower(name) {
			return errorf(KindMalformedSignatureInput,
				"The covered field %s is not lowercase, and RFC 9421 section 2.1 requires field "+
					"names in the covered list to be lowercased by the signer.", shown(name))
		}
	}
	if _, ok := entry.List.param("keyid"); requireKeyid && !ok {
		// Required with no ExpectedAID, and always under a minimum, where the profile makes keyid
		// REQUIRED even when ExpectedAID decides the key (bakobo/fiki#6). Here rather than when the
		// key is resolved: its absence belongs with the other defects of Signature-Input, ahead of
		// the covered list (@2f227n4r).
		return errorf(KindMissingKey,
			"This signature carries no keyid, which is required without an ExpectedAID and always "+
				"under a minimum covered set.")
	}
	if _, ok := entry.List.param("created"); requireCreated && !ok {
		// Only under a minimum, which is how a caller applies the KERI profile, where created is
		// REQUIRED. RFC 9421 makes it optional, and without a minimum it stays so (@7p9s3g9k).
		return errorf(KindMalformedSignatureInput,
			"This signature carries no created timestamp, which the verifier's policy requires.")
	}
	for _, p := range entry.List.Params {
		integer, known := signatureParams[p.Key]
		if !known {
			return errorf(KindMalformedSignatureInput,
				"The signature parameter %s is not one fiki understands; it accepts created, "+
					"expires, nonce, alg, keyid and tag.", shown(p.Key))
		}
		_, isInteger := p.Value.(int64)
		_, isString := p.Value.(string)
		if (integer && !isInteger) || (!integer && !isString) {
			kind := "a quoted string"
			if integer {
				kind = "an integer"
			}
			return errorf(KindMalformedSignatureInput, "The signature parameter %s must be %s.", shown(p.Key), kind)
		}
		if n, ok := p.Value.(int64); ok && n < 0 {
			// created and expires: a time before 1970 is no time a signer could have meant, refused
			// before the signature is examined (this.i @524c8qgv).
			return errorf(KindMalformedSignatureInput,
				"The signature parameter %s is %d, and a UNIX time is not negative.", shown(p.Key), n)
		}
	}
	return nil
}

// localKey is every key check that needs nothing beyond the keyid itself (profile section 9): the
// key to verify with and the identity to report when no resolver is needed, or a nil key when the
// resolver decides. Either way a keyid that is not well formed is refused here, before the expected
// keyid is compared and before any resolver sees it (this.i @5zrf8gjk).
func localKey(expectedAID, keyid string, resolve Resolver) (ed25519.PublicKey, string, error) {
	if expectedAID != "" {
		public, err := VerifyingKey(expectedAID)
		if err != nil {
			return nil, "", err
		}
		return usable(public, expectedAID, expectedAID)
	}
	if keyid == "" {
		return nil, "", errorf(KindMissingKey,
			"This signature carries no keyid and no ExpectedAID was supplied, so there is no key to verify it against.")
	}
	if resolve != nil {
		if misspelledAID(keyid) {
			return nil, "", &Error{
				Kind: KindMalformedKey,
				Message: fmt.Sprintf("The keyid %s is shaped like an AID and is not its canonical "+
					"spelling, so it is not an AID at all.", shown(keyid)),
				Keyid: keyid,
			}
		}
		return nil, "", nil
	}
	// Strictly: a lenient decoder ignores trailing bits and skips line breaks, so a keyid that is
	// not the key's encoding could verify as whatever key it happened to decode to. Only the one
	// canonical spelling is a key.
	raw, err := b64url.Strict().DecodeString(keyid)
	if !rawKeyidShape.MatchString(keyid) || err != nil {
		return nil, "", &Error{
			Kind: KindMalformedKey,
			Message: fmt.Sprintf("The keyid %s is not the canonical base64url spelling of a 32-byte "+
				"Ed25519 public key: that is exactly 43 characters from the base64url alphabet, unpadded.", shown(keyid)),
			Keyid: keyid,
		}
	}
	return usable(ed25519.PublicKey(raw), ToAID(raw), keyid)
}

// resolvedKey is the resolver's key for a keyid already found well formed, and the keyid it
// vouched for.
func resolvedKey(keyid string, resolve Resolver) (ed25519.PublicKey, string, error) {
	// The resolver is authoritative: fiki never falls back to decoding the keyid, because a
	// transferable prefix that embeds a key embeds its INCEPTION key (@6g9zjsv9).
	raw, err := resolve(keyid)
	if err != nil {
		return nil, "", err
	}
	if raw == nil {
		return nil, "", &Error{
			Kind:    KindUnknownKey,
			Message: fmt.Sprintf("No key is known for the keyid %s, so the signature cannot be checked.", shown(keyid)),
			Keyid:   keyid,
		}
	}
	if len(raw) != keyLength {
		return nil, "", &Error{
			Kind:    KindMalformedKey,
			Message: fmt.Sprintf("The key resolved for %s is not a %d-byte Ed25519 public key.", shown(keyid), keyLength),
			Keyid:   keyid,
		}
	}
	return usable(ed25519.PublicKey(raw), keyid, keyid)
}

// usable refuses a key that is not a canonical on-curve point, or is of small order, whichever way
// it arrived (@8krqtpsu). named is how the refusal names it.
func usable(public ed25519.PublicKey, aid, named string) (ed25519.PublicKey, string, error) {
	if !canonicalPoint(public) {
		return nil, "", &Error{
			Kind: KindMalformedKey,
			Message: fmt.Sprintf("The key for %s is not the canonical encoding of a point on the "+
				"Ed25519 curve, so no signature could verify under it.", shown(named)),
			Keyid: named,
		}
	}
	if smallOrder(public) {
		return nil, "", &Error{
			Kind: KindMalformedKey,
			Message: fmt.Sprintf("The key for %s is a point of small order, under which a signature "+
				"can be forged without any private key, so it is not a key fiki will verify with.", shown(named)),
			Keyid: named,
		}
	}
	return public, aid, nil
}

// checkAuthorities requires the caller's decision about the hosts it serves (@524c8qgv): Go cannot
// make a field mandatory at compile time, so leaving both Authorities and AnyAuthority unset is
// refused when the request is verified, as is stating both or an empty set, which serves no host
// at all.
func checkAuthorities(opts VerifyOptions) error {
	switch {
	case opts.Authorities == nil && !opts.AnyAuthority:
		return invalidOptions("Authorities is a required decision: pass the hosts this verifier " +
			`serves, such as []string{"api.example.com"}, or set AnyAuthority to check none.`)
	case opts.Authorities != nil && opts.AnyAuthority:
		return invalidOptions("Pass Authorities or set AnyAuthority, not both; they are opposite answers.")
	case opts.Authorities != nil && len(opts.Authorities) == 0:
		return invalidOptions("Authorities is empty, which serves no host at all; set " +
			"AnyAuthority instead to decline the check.")
	}
	return nil
}

var errBothKeyids = invalidOptions("Pass ExpectedKeyid or set AnyKeyid, not both; they are opposite answers.")

// checkExpectedKeyid requires a response verifier's decision about whose response it accepts
// (this.i @524c8qgv): Go cannot make a field mandatory at compile time, so leaving both
// ExpectedKeyid and AnyKeyid unset is refused when the response is verified. An empty
// ExpectedKeyid names no AID and is never read as the decline, which would turn a caller's
// missing value into "accept any signer"; in Go it is the same mistake as stating nothing.
func checkExpectedKeyid(opts VerifyOptions) error {
	switch {
	case opts.AnyKeyid && opts.ExpectedKeyid != "":
		return errBothKeyids
	case !opts.AnyKeyid && opts.ExpectedKeyid == "":
		return invalidOptions("ExpectedKeyid is a required decision for a response: pass the AID " +
			"you are talking to, or set AnyKeyid to accept any signer and read it from the verdict.")
	}
	return nil
}

// checkNoMinimum refuses a Minimum beside the opt-out from one, which are opposite answers.
func checkNoMinimum(opts VerifyOptions) error {
	if opts.NoMinimum && opts.Minimum != nil {
		return invalidOptions("Pass a Minimum or set NoMinimum, not both; they are opposite answers.")
	}
	return nil
}

// checkWindow refuses a freshness window that is not a positive number of seconds, as the
// caller's mistake (profile section 3, this.i @5zrf8gjk): a zero or negative one would refuse
// every honest message or none. A nil MaxAge still declines the age check, and a nil Skew is
// DefaultSkew.
func checkWindow(opts VerifyOptions) error {
	for _, w := range []struct {
		name  string
		value *int64
	}{{"MaxAge", opts.MaxAge}, {"Skew", opts.Skew}} {
		if w.value != nil && *w.value <= 0 {
			return invalidOptions("%s is %d, and a freshness window is a positive number of seconds.", w.name, *w.value)
		}
	}
	return nil
}

// later is a+b for a b that is not negative, saturating rather than wrapping, so a generous window
// can never overflow into a refusal.
func later(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// checkFreshness enforces the verifier's MaxAge, then the signer's expires (profile section 9).
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

	if opts.MaxAge != nil {
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
		created := createdValue.(int64)
		// Compared without subtracting, so no clock and no window can overflow: created is at
		// most fifteen digits and not negative, and later saturates.
		if later(created, later(maxAge, skew)) < stamp {
			return &Error{
				Kind: KindSignatureTooOld,
				Message: fmt.Sprintf("This signature was created at %d, which is more than %d seconds "+
					"before %d, so it is too old to accept.", created, maxAge, stamp),
				Created: created, Now: stamp, MaxAge: maxAge,
			}
		}
		if later(stamp, skew) < created {
			return &Error{
				Kind: KindSignatureTooOld,
				Message: fmt.Sprintf("This signature claims to have been created at %d, which is in the "+
					"future relative to %d by more than the %d-second skew allowance.", created, stamp, skew),
				Created: created, Now: stamp, MaxAge: maxAge,
			}
		}
	}

	if hasExpires {
		expires := expiresValue.(int64)
		if stamp > later(expires, skew) {
			return &Error{
				Kind: KindSignatureExpired,
				Message: fmt.Sprintf("This signature expired at %d and it is now %d, so the signer has "+
					"already declared it should not be accepted.", expires, stamp),
				Expires: expires, Now: stamp,
			}
		}
	}
	return nil
}

type recognizedDigest struct {
	name     string
	expected []byte
}

// readDigest parses a Content-Digest into the members fiki computes, or refuses it as
// MalformedDigest. Separate from the comparison so that a verifier holding two covered digests can
// parse both before hashing either: section 9 of the KERI profile puts malformed-digest first.
func readDigest(header string, present bool) ([]recognizedDigest, error) {
	if !present {
		return nil, errorf(KindMalformedDigest,
			"The signature covers content-digest, and the message carries no Content-Digest header to compare.")
	}
	order, parsed, err := parseField(header, "Content-Digest", KindMalformedDigest)
	if err != nil {
		return nil, err
	}
	var recognized []recognizedDigest
	for _, name := range order {
		if _, known := digestAlgorithms[name]; !known {
			continue
		}
		expected, ok := parsed[name].Value.([]byte)
		if !ok {
			return nil, errorf(KindMalformedDigest,
				"The %s Content-Digest is not an RFC 8941 byte sequence, so it cannot be compared with anything.", name)
		}
		recognized = append(recognized, recognizedDigest{name, expected})
	}
	if recognized == nil {
		return nil, errorf(KindMalformedDigest,
			"The Content-Digest header names no algorithm fiki computes; it computes sha-256 and sha-512.")
	}
	return recognized, nil
}

// compareDigest recomputes the digest over the body actually received (@2hwvpm42). The header is
// covered by the signature, so it cannot have been tampered with — but a covered digest still only
// attests to a body nobody hashed until somebody hashes it. Every algorithm fiki computes must
// match; the ones it does not are ignored (RFC 9530 section 2).
func compareDigest(recognized []recognizedDigest, body []byte) error {
	if body == nil {
		return errorf(KindDigestMismatch,
			"The signature covers content-digest, but no body was supplied to check it against, so the body is unverified.")
	}
	for _, digest := range recognized {
		if subtle.ConstantTimeCompare(digestAlgorithms[digest.name](body), digest.expected) != 1 {
			return errorf(KindDigestMismatch,
				"The body does not match its %s Content-Digest, so the body is not the one that was signed.", digest.name)
		}
	}
	return nil
}

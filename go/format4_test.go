package fiki

// Vectors format 4's rules (this.i @646un6k8) where the shared vectors cannot reach: each rule's
// edges one at a time, and the order a refusal is decided in.

import (
	"math/big"
	"strings"
	"testing"
)

// --- a Request that announces a body it does not carry is a caller error (@6v00d3tu) ---

const announced = "announces a body in its headers"

// announcing is a request signed for with its body, and the same request handed over without it.
func announcing(t *testing.T, key *Key, extra map[string]string) (given, stripped *Request) {
	t.Helper()
	headers := merged(extra, map[string]string{"Content-Digest": ContentDigest(testBody)})
	given = &Request{Method: "POST", URL: urlQuery, Headers: headers, Body: testBody}
	return given, &Request{Method: "POST", URL: urlQuery, Headers: headers}
}

func isAnnouncedBody(t *testing.T, err error) {
	t.Helper()
	isInvalidOptions(t, err)
	if !strings.Contains(err.Error(), announced) {
		t.Errorf("the refusal does not say the request announces a body: %v", err)
	}
}

func TestARequestAnnouncingABodyItLacksIsACallerError(t *testing.T) {
	key := testKey(t)
	for _, extra := range []map[string]string{
		{"Content-Length": "18"},
		{"Transfer-Encoding": "chunked"},
		{"Content-Length": "18", "Transfer-Encoding": "chunked"},
		{"content-length": "abc"},
		{"Transfer-Encoding": "gzip"},
	} {
		given, stripped := announcing(t, key, extra)
		headers, err := SignResponse(key, 200, given, nil, SignOptions{Created: signedAt})
		if err != nil {
			t.Fatal(err)
		}
		_, err = verifyResponseOptedOut(200, stripped, headers, VerifyOptions{Minimum: ResponseMinimum})
		isAnnouncedBody(t, err)
		_, err = SignResponse(key, 200, stripped, nil, SignOptions{Created: signedAt})
		isAnnouncedBody(t, err)
	}
}

func TestTheAnnouncedBodyIsDecidedBeforeAnySignatureHeaderIsRead(t *testing.T) {
	// V1b and N4: a malformed Signature, or none at all, never outranks the call's own mistake,
	// an unsigned 401 included, and the resolver is never asked.
	key := testKey(t)
	given, stripped := announcing(t, key, map[string]string{"Content-Length": "18"})
	signed, err := SignResponse(key, 200, given, nil, SignOptions{Created: signedAt, Keyid: keriAID})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	resolve := func(string) ([]byte, error) { calls++; return resolverFor(key)(keriAID) }
	for _, headers := range []map[string]string{merged(signed, map[string]string{"Signature": "sig=123"}),
		{}, {"Signature": ""}} {
		for _, status := range []int{200, 401} {
			_, err := verifyResponseOptedOut(status, stripped, headers, VerifyOptions{Resolve: resolve})
			isAnnouncedBody(t, err)
		}
	}
	if calls != 0 {
		t.Errorf("the resolver was asked %d times", calls)
	}
}

func TestARequestAnnouncingNoBodyAndCarryingNoneIsJudgedAsBefore(t *testing.T) {
	key := testKey(t)
	for _, length := range []string{"0", "000", " 0 "} {
		asked := &Request{Method: "GET", URL: urlQuery, Headers: map[string]string{"Content-Length": length}}
		headers, err := SignResponse(key, 200, asked, nil, SignOptions{Created: signedAt})
		if err != nil {
			t.Fatalf("%q: %v", length, err)
		}
		if _, err := verifyResponseOptedOut(200, asked, headers, VerifyOptions{Minimum: ResponseMinimum}); err != nil {
			t.Errorf("%q: %v", length, err)
		}
	}
	// A request that announces a body and carries an empty one is judged by that content: it had
	// no body, so the response binds no request digest (@7p9s3g9k).
	empty := &Request{Method: "POST", URL: urlQuery, Headers: map[string]string{"Transfer-Encoding": "chunked"}, Body: []byte{}}
	headers, err := SignResponse(key, 200, empty, nil, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := verifyResponseOptedOut(200, empty, headers, VerifyOptions{Minimum: ResponseMinimum})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(verdict.Covered, " "), "content-digest") {
		t.Errorf("covered = %v", verdict.Covered)
	}
}

// --- a Signature member that is not a byte sequence is MalformedSignature (@0zq820dl) ---

func TestASignatureMemberThatIsNotAByteSequenceIsMalformedSignature(t *testing.T) {
	headers, _ := sign(t, SignOptions{})
	for _, value := range []string{`sig="not bytes"`, "sig=1", "sig=tok", "sig=?1", "sig=1.5",
		"sig=(:AAAA:)", "sig=@1659578233"} {
		h := merged(headers, map[string]string{"Signature": value})
		if _, err := verifyOptedOut("POST", urlQuery, h, VerifyOptions{Body: testBody}); kindOf(t, err) != KindMalformedSignature {
			t.Errorf("%s: kind %s", value, kindOf(t, err))
		}
	}
	// Still ahead of the label count, which two members would otherwise fail.
	input := headers["Signature-Input"]
	h := merged(headers, map[string]string{"Signature-Input": input + ", other=" + strings.SplitN(input, "=", 2)[1],
		"Signature": `sig="not bytes", other="not bytes"`})
	if _, err := verifyOptedOut("POST", urlQuery, h, VerifyOptions{Body: testBody}); kindOf(t, err) != KindMalformedSignature {
		t.Error("the member's shape should be found before the label count")
	}
	// A byte sequence that cannot be an Ed25519 signature keeps MalformedSignatureValue.
	h = merged(headers, map[string]string{"Signature": "sig=:AAAA:"})
	if _, err := verifyOptedOut("POST", urlQuery, h, VerifyOptions{Body: testBody}); kindOf(t, err) != KindMalformedSignatureValue {
		t.Error("a short byte sequence should stay MalformedSignatureValue")
	}
}

// --- a keyid that is not a well-formed AID never reaches a resolver (@7w7nv94j) ---

// signedUnder is a GET signed by key under the keyid given.
func signedUnder(t *testing.T, key *Key, keyid string) map[string]string {
	t.Helper()
	headers, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{Created: signedAt, Keyid: keyid})
	if err != nil {
		t.Fatal(err)
	}
	return headers
}

func TestAKeyidThatIsNotAWellFormedAIDNeverReachesAResolver(t *testing.T) {
	// N3: aid-lens.json's malformed shapes as keyids, any other string, and fiki's own raw keyid,
	// which a verifier given a resolver refuses too (@7w7nv94j's tradeoff).
	key := testKey(t)
	for _, keyid := range []string{
		"BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG",  // 43 characters
		"AAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4", // code A
		"BQOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4", // a padding-bit alias of a B AID
		paddingBitAlias(keriAID),
		"E" + strings.Repeat("!", 43),
		"not-an-aid",
		key.Keyid(),
	} {
		calls := 0
		resolve := func(string) ([]byte, error) { calls++; return nil, nil }
		_, err := verifyOptedOut("GET", urlQuery, signedUnder(t, key, keyid), VerifyOptions{Resolve: resolve})
		if kindOf(t, err) != KindMalformedKey || calls != 0 {
			t.Errorf("%q: kind %s after %d resolver calls", keyid, kindOf(t, err), calls)
		}
	}
}

func TestAWellFormedKeyidIsAskedOfTheResolverOnce(t *testing.T) {
	key := testKey(t)
	var asked []string
	unknown := func(keyid string) ([]byte, error) { asked = append(asked, keyid); return nil, nil }
	_, err := verifyOptedOut("GET", urlQuery, signedUnder(t, key, keriAID), VerifyOptions{Resolve: unknown})
	if kindOf(t, err) != KindUnknownKey || len(asked) != 1 || asked[0] != keriAID {
		t.Errorf("kind %s, resolver asked %q", kindOf(t, err), asked)
	}
	// A small-order B AID is well formed, so the resolver is asked, and the key it returns is
	// refused (aid-lens.json's small-order-b-aid).
	weak := "BAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	asked = nil
	prefix := func(keyid string) ([]byte, error) {
		asked = append(asked, keyid)
		return append([]byte{1}, make([]byte, 31)...), nil
	}
	_, err = verifyOptedOut("GET", urlQuery, signedUnder(t, key, weak), VerifyOptions{Resolve: prefix})
	if kindOf(t, err) != KindMalformedKey || len(asked) != 1 {
		t.Errorf("kind %s, resolver asked %q", kindOf(t, err), asked)
	}
	// The same check on a response, before the expected keyid is compared.
	headers, err := SignResponse(key, 200, nil, nil, SignOptions{Created: signedAt, Keyid: "not-an-aid"})
	if err != nil {
		t.Fatal(err)
	}
	asked = nil
	_, err = verifyResponseOptedOut(200, nil, headers, VerifyOptions{Resolve: unknown, ExpectedKeyid: String(keriAID)})
	if kindOf(t, err) != KindMalformedKey || len(asked) != 0 {
		t.Errorf("kind %s, resolver asked %q", kindOf(t, err), asked)
	}
}

func TestVerifyingKeyRefusesAWeakKey(t *testing.T) {
	// The identity point, and an encoding that is not a point on the curve: VerifyingKey refuses
	// both itself, as the AID decoder every port's aid-lens driver calls (@7w7nv94j).
	for _, aid := range []string{"BAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ToAID(nonCanonicalPoint(t))} {
		if _, err := VerifyingKey(aid); kindOf(t, err) != KindMalformedKey {
			t.Errorf("%s should be MalformedKey", aid)
		}
	}
}

// nonCanonicalPoint encodes y = p + 2, which is no canonical encoding of any point.
func nonCanonicalPoint(t *testing.T) []byte {
	t.Helper()
	key := encodeY(new(big.Int).Add(curveP, big.NewInt(2)), false)
	if canonicalPoint(key) {
		t.Fatal("y = p + 2 should not be canonical")
	}
	return key
}

// --- an explicitly empty expected AID is MalformedKey, as in the other five ports (@7j58rwu2) ---

func TestAnEmptyExpectedAIDIsMalformedKey(t *testing.T) {
	// An empty AID is a string that is not an AID, so the AID decoder refuses it, as any other;
	// nil still states none, and an empty ExpectedKeyid stays the caller's mistake.
	key := testKey(t)
	headers := signedUnder(t, key, "")
	_, err := verifyOptedOut("GET", urlQuery, headers, VerifyOptions{ExpectedAID: String("")})
	if kindOf(t, err) != KindMalformedKey {
		t.Error("an empty ExpectedAID on a request should be MalformedKey")
	}
	statusOnly, err := SignResponse(key, 200, nil, nil, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifyResponseOptedOut(200, nil, statusOnly, VerifyOptions{ExpectedAID: String("")})
	if kindOf(t, err) != KindMalformedKey {
		t.Error("an empty ExpectedAID on a response should be MalformedKey")
	}
	_, err = verifyOptedOut("GET", urlQuery, headers, VerifyOptions{ExpectedAID: String(""), ExpectedKeyid: String("")})
	isInvalidOptions(t, err)
}

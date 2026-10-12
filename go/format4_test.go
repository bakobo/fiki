package fiki

// Vectors format 4's rules (this.i @646un6k8) where the shared vectors cannot reach: each rule's
// edges one at a time, and the order a refusal is decided in.

import (
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

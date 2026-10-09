package fiki

// A hostile review of 365f522 on bakobo/fiki#6: each claim tried against the port.

import (
	"testing"
)

func TestAHeadersMapWithTwoSpellingsOfOneFieldIsRefused(t *testing.T) {
	// The base and the digest check each lowercased the map on their own, and Go's map order could
	// give one the signed Content-Digest and the other the substituted one.
	key := testKey(t)
	signed, err := SignRequest(key, "POST", urlQuery, nil, SignOptions{Body: testBody, Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	evil := []byte(`{"hello": "mallory"}`)
	headers := merged(signed, map[string]string{"content-digest": ContentDigest(evil)})
	for i := 0; i < 200; i++ {
		_, err := verifyOptedOut("POST", urlQuery, headers, VerifyOptions{Body: evil})
		if err == nil {
			t.Fatalf("a substituted body verified on attempt %d", i)
		}
		isInvalidOptions(t, err)
	}
	dup := map[string]string{"X-A": "1", "x-a": "2"}
	_, err = SignRequest(key, "GET", urlQuery, dup, SignOptions{})
	isInvalidOptions(t, err)
	_, err = SignatureBase("GET", urlQuery, dup, []string{"@method"}, SignatureParams{Created: 1})
	isInvalidOptions(t, err)
	request := &Request{Method: "GET", URL: urlQuery, Headers: dup}
	_, err = SignResponse(key, 200, request, nil, SignOptions{})
	isInvalidOptions(t, err)
	_, err = SignResponse(key, 200, nil, dup, SignOptions{})
	isInvalidOptions(t, err)
	_, err = ResponseSignatureBase(200, request, nil, []string{"@status"}, SignatureParams{Created: 1})
	isInvalidOptions(t, err)
	_, err = verifyResponseOptedOut(200, nil, merged(dup, signed), VerifyOptions{})
	isInvalidOptions(t, err)
	_, err = verifyResponseOptedOut(200, request, signed, VerifyOptions{})
	isInvalidOptions(t, err)
}

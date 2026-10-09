package fiki

import (
	"errors"
	"strings"
	"testing"
)

// An empty method is a mistake in the call, never the text of @method (the js port's third
// hostile-review defect).
func TestAnEmptyMethodIsTheCallersMistake(t *testing.T) {
	key := testKey(t)
	_, err := SignRequest(key, "", urlQuery, nil, SignOptions{})
	isInvalidOptions(t, err)
	headers, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifyOptedOut("", urlQuery, headers, VerifyOptions{})
	isInvalidOptions(t, err)
	_, err = SignResponse(key, 200, &Request{URL: urlQuery}, nil, SignOptions{})
	isInvalidOptions(t, err)
	if errors.Is(err, ErrInvalidOptions) && !strings.Contains(err.Error(), "method") {
		t.Errorf("the error should name the method: %v", err)
	}
}

// Copilot on bakobo/fiki#6: the method is refused when empty whether or not @method is covered,
// on every request path, including the request a response is bound to.
func TestAnEmptyMethodIsRefusedEvenWhenUncovered(t *testing.T) {
	key := testKey(t)
	uncovered := []string{"@path", "@query"}
	_, err := SignRequest(key, "", urlQuery, nil, SignOptions{Covered: uncovered})
	isInvalidOptions(t, err)
	_, err = SignatureBase("", urlQuery, nil, uncovered, SignatureParams{Created: 1})
	isInvalidOptions(t, err)
	headers, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{Covered: uncovered, Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifyOptedOut("", urlQuery, headers, VerifyOptions{})
	isInvalidOptions(t, err)
	methodless := &Request{URL: urlQuery}
	_, err = SignResponse(key, 200, methodless, nil, SignOptions{Covered: []string{"@status"}})
	isInvalidOptions(t, err)
	_, err = ResponseSignatureBase(200, methodless, nil, []string{"@status"}, SignatureParams{Created: 1})
	isInvalidOptions(t, err)
	response, err := SignResponse(key, 200, nil, nil, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifyResponseOptedOut(200, methodless, response, VerifyOptions{})
	isInvalidOptions(t, err)
}

// Copilot on bakobo/fiki#6: an empty Signature header on a 401 is as unsigned as an absent one.
// One of only whitespace is present, as every port says alike (review B7), so it is not
// Unauthenticated; 0.8's Go alone trimmed it to nothing. Present, it is then read in section 9's
// order: with no Signature-Input that absence is found first, and with one the Signature fails to
// parse.
func TestAnEmptySignatureHeaderOnA401IsUnauthenticated(t *testing.T) {
	_, err := verifyResponseOptedOut(401, nil, map[string]string{"Signature": ""}, VerifyOptions{})
	if kindOf(t, err) != KindUnauthenticated {
		t.Errorf("expected Unauthenticated, got %v", err)
	}
	_, err = verifyResponseOptedOut(401, nil, map[string]string{"Signature": " \t"}, VerifyOptions{})
	if kindOf(t, err) != KindMissingSignatureInput {
		t.Errorf("expected MissingSignatureInput, got %v", err)
	}
	_, err = verifyResponseOptedOut(401, nil, map[string]string{"Signature": " \t", "Signature-Input": `sig=("@status")`}, VerifyOptions{})
	if kindOf(t, err) != KindMalformedSignature {
		t.Errorf("expected MalformedSignature, got %v", err)
	}
}

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
	_, err = VerifyRequest("", urlQuery, headers, VerifyOptions{})
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
	_, err = VerifyRequest("", urlQuery, headers, VerifyOptions{})
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
	_, err = VerifyResponse(200, methodless, response, VerifyOptions{})
	isInvalidOptions(t, err)
}

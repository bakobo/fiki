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

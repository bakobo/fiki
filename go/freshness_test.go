package fiki

// 0.9.0 (this.i @65u2932c): MaxAge is a required decision in Go as in every other port, so a
// verifier that never wrote one is refused rather than read as declining the check, and the
// optional strings ExpectedAID and ExpectedKeyid are pointers, so a stated empty one is the
// caller's mistake rather than "unset" (tick 5kyt).

import (
	"strings"
	"testing"
)

func TestFreshnessIsARequiredDecision(t *testing.T) {
	key := testKey(t)
	headers, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	statusOnly, err := SignResponse(key, 200, nil, nil, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	request := &Request{Method: "GET", URL: urlQuery}
	onRequest := func(opts VerifyOptions) error {
		opts.NoMinimum, opts.AnyAuthority = true, true
		_, err := VerifyRequest("GET", urlQuery, headers, opts)
		return err
	}
	onResponse := func(opts VerifyOptions) error {
		opts.NoMinimum, opts.AnyKeyid = true, true
		_, err := VerifyResponse(200, request, statusOnly, opts)
		return err
	}

	for side, verify := range map[string]func(VerifyOptions) error{"request": onRequest, "response": onResponse} {
		t.Run(side+": no decision about age is the caller's mistake", func(t *testing.T) {
			err := verify(VerifyOptions{})
			isInvalidOptions(t, err)
			if !strings.Contains(err.Error(), "MaxAge") || !strings.Contains(err.Error(), "AnyAge") {
				t.Errorf("the refusal should name both ways to decide: %v", err)
			}
		})
		t.Run(side+": both MaxAge and AnyAge is the caller's mistake", func(t *testing.T) {
			isInvalidOptions(t, verify(VerifyOptions{MaxAge: maxAge(300), AnyAge: true, Now: signedAt}))
		})
		t.Run(side+": a MaxAge that is not positive is still the caller's mistake", func(t *testing.T) {
			isInvalidOptions(t, verify(VerifyOptions{MaxAge: maxAge(0)}))
		})
		t.Run(side+": AnyAge is the explicit decline, and verifies", func(t *testing.T) {
			if err := verify(VerifyOptions{AnyAge: true}); err != nil {
				t.Error(err)
			}
		})
		t.Run(side+": a MaxAge verifies a fresh message", func(t *testing.T) {
			if err := verify(VerifyOptions{MaxAge: maxAge(300), Now: signedAt}); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestOptionalStringsArePointers(t *testing.T) {
	if s := String("x"); s == nil || *s != "x" {
		t.Fatalf("String(%q) = %v", "x", s)
	}
	key := testKey(t)
	headers, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	statusOnly, err := SignResponse(key, 200, nil, nil, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	request := &Request{Method: "GET", URL: urlQuery}

	for name, opts := range map[string]VerifyOptions{
		"a stated empty ExpectedAID":    {ExpectedAID: String("")},
		"a stated empty ExpectedKeyid":  {ExpectedKeyid: String("")},
		"ExpectedKeyid beside AnyKeyid": {ExpectedKeyid: String(key.Keyid()), AnyKeyid: true},
	} {
		t.Run(name+" on a request is the caller's mistake", func(t *testing.T) {
			opts.NoMinimum, opts.AnyAuthority, opts.AnyAge = true, true, true
			_, err := VerifyRequest("GET", urlQuery, headers, opts)
			isInvalidOptions(t, err)
		})
	}
	for name, opts := range map[string]VerifyOptions{
		"a stated empty ExpectedAID":   {ExpectedAID: String(""), AnyKeyid: true},
		"a stated empty ExpectedKeyid": {ExpectedKeyid: String("")},
		"no decision about the keyid":  {},
	} {
		t.Run(name+" on a response is the caller's mistake", func(t *testing.T) {
			opts.NoMinimum, opts.AnyAge = true, true
			_, err := VerifyResponse(200, request, statusOnly, opts)
			isInvalidOptions(t, err)
		})
	}
	t.Run("a stated empty ExpectedKeyid is not reported as a missing decision", func(t *testing.T) {
		_, err := VerifyResponse(200, request, statusOnly, VerifyOptions{NoMinimum: true, AnyAge: true, ExpectedKeyid: String("")})
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Errorf("expected a refusal naming the empty value, got %v", err)
		}
	})

	t.Run("nil is unset: no ExpectedAID and no ExpectedKeyid on a request verifies", func(t *testing.T) {
		if _, err := VerifyRequest("GET", urlQuery, headers,
			VerifyOptions{NoMinimum: true, AnyAuthority: true, AnyAge: true}); err != nil {
			t.Error(err)
		}
	})
	t.Run("a stated ExpectedAID and ExpectedKeyid verify their signer", func(t *testing.T) {
		verdict, err := VerifyRequest("GET", urlQuery, headers, VerifyOptions{NoMinimum: true,
			AnyAuthority: true, AnyAge: true, ExpectedAID: String(key.AID()), ExpectedKeyid: String(key.Keyid())})
		if err != nil || verdict.AID != key.AID() {
			t.Errorf("verdict %+v, err %v", verdict, err)
		}
		if _, err := VerifyResponse(200, request, statusOnly, VerifyOptions{NoMinimum: true, AnyAge: true,
			ExpectedKeyid: String(key.Keyid())}); err != nil {
			t.Error(err)
		}
	})
	t.Run("a stated ExpectedKeyid still refuses another signer", func(t *testing.T) {
		_, err := VerifyRequest("GET", urlQuery, headers, VerifyOptions{NoMinimum: true, AnyAuthority: true,
			AnyAge: true, ExpectedKeyid: String(keriAID)})
		if kindOf(t, err) != KindUnknownKey {
			t.Errorf("expected UnknownKey, got %v", err)
		}
	})
}

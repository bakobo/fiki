package fiki_test

// The samples in docs/user-guide.md, run.
//
// A guide whose code does not compile is worse than no guide: a reader trusts it, pastes it, and
// loses an hour to an API that moved. This is an external test package on purpose, so it sees only
// what a consumer sees.

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	fiki "github.com/bakobo/fiki/go"
)

func TestTheGuidesSamplesRun(t *testing.T) {
	key := fiki.Generate()
	if len(key.AID()) != 44 {
		t.Fatalf("an AID is 44 characters, got %d", len(key.AID()))
	}

	url := "https://api.example.com/things?limit=1"
	body := []byte(`{"hello": "world"}`)
	headers, err := fiki.SignRequest(key, "POST", url, nil, fiki.SignOptions{Body: body})
	if err != nil {
		t.Fatal(err)
	}

	maxAge := int64(300)
	verdict, err := fiki.VerifyRequest("POST", url, headers,
		fiki.VerifyOptions{Body: body, MaxAge: &maxAge, Authorities: []string{"api.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.AID != key.AID() {
		t.Errorf("AID = %q, want %q", verdict.AID, key.AID())
	}
}

// The KERI-profile samples in the Go guide (`this.i` @9z57sejw), each run as written. The keys and
// the AID come from vectors/keri/'s keys table: a controller and the agent that serves it.

func guideKey(t *testing.T, first byte) *fiki.Key {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = first + byte(i)
	}
	key, err := fiki.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestTheGuidesKeriProfileSamplesRun(t *testing.T) {
	key := guideKey(t, 2)      // the controller's current signing key
	agentKey := guideKey(t, 3) // the agent's
	aid := "ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx"
	agentAID := "EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6"
	url := "https://keria.example.com/identifiers?type=rot"
	body := []byte(`{"name": "alice"}`)
	public := func(k *fiki.Key) []byte { raw, _ := fiki.VerifyingKey(k.AID()); return raw }
	keyState := map[string][]byte{aid: public(key), agentAID: public(agentKey)}

	// (a) Signing a request with a KERI AID as the keyid.
	headers, err := fiki.SignRequest(key, "POST", url, nil, fiki.SignOptions{
		Keyid:   aid,                 // name the AID; the verifier resolves it
		Body:    body,                // covered by a Content-Digest, returned among the headers
		Minimum: fiki.RequestMinimum, // refuse to sign what a profile verifier would refuse
	})
	if err != nil {
		t.Fatal(err)
	}

	// (b) Verifying a request with a resolver.
	resolve := func(keyid string) ([]byte, error) {
		key, ok := keyState[keyid] // the current key of the KEL you hold for keyid
		if !ok {
			return nil, nil // no KEL: fiki refuses the message as UnknownKey
		}
		return key, nil
	}
	maxAge, skew := int64(300), int64(60)
	verdict, err := fiki.VerifyRequest("POST", url, headers, fiki.VerifyOptions{
		Body:        body,
		Resolve:     resolve,
		Minimum:     fiki.RequestMinimum,
		MaxAge:      &maxAge,
		Skew:        &skew,
		Authorities: []string{"keria.example.com"}, // the authorities this server answers for
	})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Keyid != aid || verdict.AID != aid {
		t.Errorf("verdict = %+v", verdict)
	}

	// (c) Signing a response.
	request := &fiki.Request{Method: "POST", URL: url, Headers: headers, Body: body}
	responseBody := []byte(`{"done": true}`)
	responseHeaders, err := fiki.SignResponse(agentKey, 200, request, nil, fiki.SignOptions{
		Keyid:   agentAID,
		Body:    responseBody,
		Minimum: fiki.ResponseMinimum,
	})
	if err != nil {
		t.Fatal(err)
	}

	// (d) Verifying a response.
	verdict, err = fiki.VerifyResponse(200, request, responseHeaders, fiki.VerifyOptions{
		Body:          responseBody,
		Resolve:       resolve,
		Minimum:       fiki.ResponseMinimum,
		ExpectedKeyid: fiki.String(agentAID), // the AID you meant to talk to (profile R1)
		MaxAge:        &maxAge,
		Skew:          &skew,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Covered[len(verdict.Covered)-1] != `"content-digest";req` {
		t.Errorf("covered = %v", verdict.Covered)
	}

	// (e) The new error kinds.
	describe := func(err error) string {
		var refusal *fiki.Error
		switch {
		case errors.Is(err, fiki.ErrInvalidOptions):
			return "a mistake in the call, not in the message"
		case errors.As(err, &refusal):
			switch refusal.Kind {
			case fiki.KindUnknownKey:
				return "no key state for " + refusal.Keyid
			case fiki.KindUnsupportedSigner:
				return "no single key of " + refusal.Keyid + " signs alone"
			case fiki.KindInsufficientCoverage:
				return "the signature does not cover " + refusal.Component
			case fiki.KindDuplicateComponent:
				return "the covered list names " + refusal.Component + " twice"
			case fiki.KindUnauthenticated:
				return "an unsigned 401; its body is not to be trusted"
			}
			return refusal.Kind
		}
		return err.Error()
	}

	_, err = fiki.VerifyRequest("POST", url, headers, fiki.VerifyOptions{
		Body: body, Minimum: fiki.RequestMinimum, Authorities: []string{"keria.example.com"}, MaxAge: &maxAge,
		Resolve: func(string) ([]byte, error) { return nil, nil },
	})
	if got := describe(err); got != "no key state for "+aid {
		t.Errorf("UnknownKey: %s", got)
	}
	twoOfThree := func(keyid string) ([]byte, error) {
		return nil, &fiki.Error{Kind: fiki.KindUnsupportedSigner, Keyid: keyid,
			Message: "The key state of " + keyid + " has no single key that satisfies its threshold."}
	}
	_, err = fiki.VerifyRequest("POST", url, headers, fiki.VerifyOptions{Body: body, Resolve: twoOfThree,
		Authorities: []string{"keria.example.com"}, MaxAge: &maxAge})
	if got := describe(err); got != "no single key of "+aid+" signs alone" {
		t.Errorf("UnsupportedSigner: %s", got)
	}
	_, err = fiki.VerifyResponse(200, request, responseHeaders, fiki.VerifyOptions{
		Body: responseBody, Resolve: resolve, Minimum: append(fiki.ResponseMinimum[:4:4], "content-type"),
		ExpectedKeyid: fiki.String(agentAID), MaxAge: &maxAge,
	})
	if got := describe(err); got != "the signature does not cover content-type" {
		t.Errorf("InsufficientCoverage: %s", got)
	}
	_, err = fiki.SignRequest(key, "GET", url, nil, fiki.SignOptions{Covered: []string{"@method", "@path", "@query", "@path"}})
	if got := describe(err); got != "the covered list names @path twice" {
		t.Errorf("DuplicateComponent: %s", got)
	}
	_, err = fiki.VerifyResponse(401, request, map[string]string{}, fiki.VerifyOptions{AnyKeyid: true, MaxAge: &maxAge})
	if got := describe(err); got != "an unsigned 401; its body is not to be trusted" {
		t.Errorf("Unauthenticated: %s", got)
	}
	_, err = fiki.VerifyRequest("POST", url, headers, fiki.VerifyOptions{Minimum: []string{"@method"}, MaxAge: &maxAge})
	if got := describe(err); got != "a mistake in the call, not in the message" {
		t.Errorf("ErrInvalidOptions: %s", got)
	}
	_, err = fiki.VerifyRequest("POST", url, map[string]string{}, fiki.VerifyOptions{
		Authorities: []string{"keria.example.com"}, MaxAge: &maxAge})
	if got := describe(err); got != fiki.KindMissingSignature {
		t.Errorf("other kinds: %s", got)
	}
	if got := describe(errors.New("not fiki's")); got != "not fiki's" {
		t.Errorf("other errors: %s", got)
	}
}

// verifySample is the Go block under "Verifying a request" in a markdown file.
func verifySample(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	at := strings.Index(text, "## Verifying a request")
	if at < 0 {
		t.Fatalf("%s has no section on verifying a request", path)
	}
	block := regexp.MustCompile("(?s)```go\n(.*?)```").FindStringSubmatch(text[at:])
	if block == nil {
		t.Fatalf("%s has no Go sample for verifying a request", path)
	}
	return block[1]
}

// Review A10: net/http moves Host out of r.Header into r.Host, so a sample that copied r.Header
// alone never carried the authority, and a default-covered request failed as MissingComponent.
// The README's sample is the guide's, and the handler below runs it as written, inside a real
// net/http server, against a request sent by net/http.
func TestTheVerifySampleWorksInsideANetHTTPServer(t *testing.T) {
	sample := verifySample(t, "README.md")
	if guide := verifySample(t, "../docs/user-guide.md"); sample != guide {
		t.Fatalf("README.md's verify sample is not the guide's:\n%s\nthe guide's:\n%s", sample, guide)
	}
	source, err := os.ReadFile("guide_test.go")
	if err != nil {
		t.Fatal(err)
	}
	dedent := regexp.MustCompile(`(?m)^[ \t]+`)
	if !strings.Contains(dedent.ReplaceAllString(string(source), ""), dedent.ReplaceAllString(sample, "")) {
		t.Fatalf("the handler in this test does not run the sample as written:\n%s", sample)
	}

	type outcome struct {
		verdict *fiki.Verdict
		err     error
	}
	outcomes := make(chan outcome, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// The sample, as written in README.md and docs/user-guide.md:
		// net/http moves Host out of r.Header into r.Host, so put it back: it is the authority.
		headers := map[string]string{"host": r.Host}
		for name, values := range r.Header {
			headers[name] = strings.Join(values, ", ")
		}
		maxAge := int64(300)
		verdict, err := fiki.VerifyRequest(r.Method, r.RequestURI, headers,
			fiki.VerifyOptions{Body: body, MaxAge: &maxAge, Authorities: []string{"api.example.com"}})
		outcomes <- outcome{verdict, err}
	}))
	defer server.Close()

	key := fiki.Generate()
	body := []byte(`{"hello": "world"}`)
	signed, err := fiki.SignRequest(key, "POST", "http://api.example.com/things?limit=1", nil,
		fiki.SignOptions{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest("POST", server.URL+"/things?limit=1", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "api.example.com" // the authority it was signed for, sent to the test server
	for name, value := range signed {
		request.Header.Set(name, value)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	got := <-outcomes
	if got.err != nil {
		t.Fatalf("the sample refused a request fiki signed: %v", got.err)
	}
	if got.verdict.AID != key.AID() {
		t.Errorf("AID = %q, want %q", got.verdict.AID, key.AID())
	}
}

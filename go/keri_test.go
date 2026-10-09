package fiki

// The KERI-profile surface beyond what vectors/keri/ pins (`this.i` @9z57sejw): signing responses,
// a caller's mistakes as ErrInvalidOptions, the resolver's contract, the wire refusals one at a
// time, and the parser and URL splitting the profile's components rest on.

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

const keriAID = "ELLKuZrOw7_eNOyM2TXu5j2YHnEyHnpM1iTUKf4Dxgtx"

// zeroSignature is a well-formed Signature header whose value verifies nothing, for refusals that
// must fire before the signature is checked.
var zeroSignature = "sig=:" + b64std(make([]byte, 64)) + ":"

func resolverFor(key *Key) Resolver {
	return func(keyid string) ([]byte, error) {
		if keyid == keriAID {
			return []byte(key.private.Public().(ed25519.PublicKey)), nil
		}
		return nil, nil
	}
}

func isInvalidOptions(t *testing.T, err error) {
	t.Helper()
	var fikiErr *Error
	if !errors.Is(err, ErrInvalidOptions) || errors.As(err, &fikiErr) {
		t.Fatalf("expected ErrInvalidOptions and no *Error, got %T: %v", err, err)
	}
}

func merged(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// signedRequest is a POST with a body, signed under a KERI AID keyid.
func signedRequest(t *testing.T, key *Key) *Request {
	t.Helper()
	headers, err := SignRequest(key, "POST", urlQuery, nil,
		SignOptions{Body: testBody, Created: signedAt, Keyid: keriAID, Minimum: RequestMinimum})
	if err != nil {
		t.Fatal(err)
	}
	return &Request{Method: "POST", URL: urlQuery, Headers: headers, Body: testBody}
}

func TestSignAndVerifyResponses(t *testing.T) {
	key := testKey(t)
	request := signedRequest(t, key)
	body := []byte(`{"done": true}`)
	verifyOpts := func() VerifyOptions {
		return VerifyOptions{Body: body, Resolve: resolverFor(key), Minimum: ResponseMinimum,
			ExpectedKeyid: keriAID, MaxAge: maxAge(300), Now: signedAt}
	}

	t.Run("a default response binds the request, its body included, and verifies", func(t *testing.T) {
		headers, err := SignResponse(key, 200, request, nil,
			SignOptions{Body: body, Created: signedAt, Keyid: keriAID, Minimum: ResponseMinimum})
		if err != nil {
			t.Fatal(err)
		}
		verdict, err := verifyResponseOptedOut(200, request, merged(headers), verifyOpts())
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"@status", `"@method";req`, `"@path";req`, `"@query";req`, "content-digest", `"content-digest";req`}
		if strings.Join(verdict.Covered, " ") != strings.Join(want, " ") {
			t.Errorf("covered = %v, want %v", verdict.Covered, want)
		}
		if verdict.AID != keriAID || verdict.Keyid != keriAID {
			t.Errorf("verdict = %+v", verdict)
		}
		if _, err := verifyResponseOptedOut(201, request, headers, verifyOpts()); kindOf(t, err) != KindSignatureMismatch {
			t.Error("an altered status should not verify")
		}
	})

	t.Run("a response with no request covers its status alone", func(t *testing.T) {
		headers, err := SignResponse(key, 204, nil, nil, SignOptions{Created: signedAt})
		if err != nil {
			t.Fatal(err)
		}
		verdict, err := verifyResponseOptedOut(204, nil, headers, VerifyOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(verdict.Covered, " ") != "@status" || verdict.AID != key.AID() {
			t.Errorf("verdict = %+v", verdict)
		}
	})

	t.Run("a request body with no digest to bind is refused", func(t *testing.T) {
		bare := &Request{Method: "POST", URL: urlQuery, Body: testBody}
		_, err := SignResponse(key, 200, bare, nil, SignOptions{})
		if kindOf(t, err) != KindUncoveredBody {
			t.Error("expected UncoveredBody")
		}
	})

	t.Run("a chosen covered list below the minimum is refused at signing", func(t *testing.T) {
		_, err := SignResponse(key, 200, request, nil, SignOptions{Covered: []string{"@status"}, Minimum: ResponseMinimum})
		if kindOf(t, err) != KindInsufficientCoverage {
			t.Error("expected InsufficientCoverage")
		}
	})

	t.Run("a chosen covered list omitting the body's digest is refused", func(t *testing.T) {
		_, err := SignResponse(key, 200, nil, nil, SignOptions{Body: body, Covered: []string{"@status"}})
		if kindOf(t, err) != KindUncoveredBody {
			t.Error("expected UncoveredBody")
		}
	})

	t.Run("a signer does not vouch for a request digest its body contradicts", func(t *testing.T) {
		swapped := *request
		swapped.Body = []byte("something else")
		covered := []string{"@status", Req("@method"), Req("@path"), Req("@query"), Req("content-digest")}
		_, err := SignResponse(key, 200, &swapped, nil, SignOptions{Covered: covered})
		if kindOf(t, err) != KindDigestMismatch {
			t.Error("expected DigestMismatch")
		}
		undigested := &Request{Method: "POST", URL: urlQuery, Body: testBody}
		_, err = SignResponse(key, 200, undigested, nil, SignOptions{Covered: covered})
		if kindOf(t, err) != KindMalformedDigest {
			t.Error("a bound request digest that is absent should be MalformedDigest")
		}
		unparsable := &Request{Method: "POST", URL: urlQuery, Body: testBody, Headers: map[string]string{"Content-Digest": "((("}}
		_, err = SignResponse(key, 200, unparsable, nil, SignOptions{Covered: covered})
		if kindOf(t, err) != KindMalformedDigest {
			t.Error("expected MalformedDigest")
		}
	})

	t.Run("a req component with no request is refused", func(t *testing.T) {
		_, err := SignResponse(key, 200, nil, nil, SignOptions{Covered: []string{"@status", Req("@path")}})
		if kindOf(t, err) != KindMissingComponent {
			t.Error("expected MissingComponent")
		}
	})

	t.Run("an unreadable component spec is refused", func(t *testing.T) {
		_, err := SignResponse(key, 200, nil, nil, SignOptions{Covered: []string{`"@status`}})
		if kindOf(t, err) != KindUnsupportedComponent {
			t.Error("expected UnsupportedComponent")
		}
	})

	t.Run("an unsigned 401 is Unauthenticated, before anything else", func(t *testing.T) {
		_, err := verifyResponseOptedOut(401, request, map[string]string{"Content-Type": "text/plain"}, verifyOpts())
		if kindOf(t, err) != KindUnauthenticated {
			t.Error("expected Unauthenticated")
		}
		_, err = verifyResponseOptedOut(200, request, map[string]string{}, verifyOpts())
		if kindOf(t, err) != KindMissingSignature {
			t.Error("an unsigned 200 is MissingSignature")
		}
	})

	t.Run("the caller's mistakes are ErrInvalidOptions", func(t *testing.T) {
		headers, err := SignResponse(key, 200, request, nil, SignOptions{Body: body, Created: signedAt, Keyid: keriAID})
		if err != nil {
			t.Fatal(err)
		}
		opts := verifyOpts()
		opts.Authorities = []string{"api.example.com"}
		_, err = verifyResponseOptedOut(200, request, headers, opts)
		isInvalidOptions(t, err)

		opts = verifyOpts()
		opts.Minimum = []string{"@status"}
		_, err = verifyResponseOptedOut(200, request, headers, opts)
		isInvalidOptions(t, err)

		bodiless := *request
		bodiless.Body = nil
		_, err = verifyResponseOptedOut(200, &bodiless, headers, VerifyOptions{Body: body, Resolve: resolverFor(key)})
		isInvalidOptions(t, err)

		_, err = SignResponse(key, 200, request, nil, SignOptions{Minimum: []string{}})
		isInvalidOptions(t, err)
	})

	t.Run("a status that is not three digits has no status line", func(t *testing.T) {
		_, err := ResponseSignatureBase(42, nil, nil, []string{"@status"}, SignatureParams{Created: 1})
		if kindOf(t, err) != KindMissingComponent {
			t.Error("expected MissingComponent")
		}
		_, err = ResponseSignatureBase(200, nil, nil, []string{`"@status";`}, SignatureParams{Created: 1})
		if kindOf(t, err) != KindUnsupportedComponent {
			t.Error("expected UnsupportedComponent")
		}
	})
}

func TestCallerChosenKeyidsAndResolvers(t *testing.T) {
	key := testKey(t)
	request := signedRequest(t, key)
	opts := func(resolve Resolver) VerifyOptions {
		return VerifyOptions{Body: testBody, Resolve: resolve, Minimum: RequestMinimum}
	}

	t.Run("a resolver supplies the key and the verdict names the keyid", func(t *testing.T) {
		verdict, err := verifyOptedOut("POST", urlQuery, request.Headers, opts(resolverFor(key)))
		if err != nil {
			t.Fatal(err)
		}
		if verdict.AID != keriAID || verdict.Keyid != keriAID {
			t.Errorf("verdict = %+v", verdict)
		}
	})

	t.Run("a resolver that knows no key is UnknownKey", func(t *testing.T) {
		_, err := verifyOptedOut("POST", urlQuery, request.Headers, opts(func(string) ([]byte, error) { return nil, nil }))
		if kindOf(t, err) != KindUnknownKey {
			t.Error("expected UnknownKey")
		}
	})

	t.Run("a resolver's own refusal passes through unchanged", func(t *testing.T) {
		refusal := &Error{Kind: KindUnsupportedSigner, Message: "two of three", Keyid: keriAID}
		_, err := verifyOptedOut("POST", urlQuery, request.Headers, opts(func(string) ([]byte, error) { return nil, refusal }))
		if err != refusal {
			t.Errorf("got %v", err)
		}
	})

	t.Run("a resolved key of the wrong length is MalformedKey", func(t *testing.T) {
		_, err := verifyOptedOut("POST", urlQuery, request.Headers, opts(func(string) ([]byte, error) { return []byte{}, nil }))
		if kindOf(t, err) != KindMalformedKey {
			t.Error("expected MalformedKey")
		}
	})

	t.Run("a misspelled AID is refused before any resolver sees it", func(t *testing.T) {
		alias := paddingBitAlias(keriAID)
		headers, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{Created: signedAt, Keyid: alias})
		if err != nil {
			t.Fatal(err)
		}
		called := false
		_, err = verifyOptedOut("GET", urlQuery, headers, VerifyOptions{Resolve: func(string) ([]byte, error) {
			called = true
			return nil, nil
		}})
		if kindOf(t, err) != KindMalformedKey || called {
			t.Error("expected MalformedKey without a resolver call")
		}
	})

	t.Run("an expected keyid refuses any other", func(t *testing.T) {
		o := opts(resolverFor(key))
		o.ExpectedKeyid = "Esomebody-else"
		_, err := verifyOptedOut("POST", urlQuery, request.Headers, o)
		if kindOf(t, err) != KindUnknownKey {
			t.Error("expected UnknownKey")
		}
	})

	t.Run("ExpectedAID and Resolve together are ErrInvalidOptions", func(t *testing.T) {
		o := opts(resolverFor(key))
		o.ExpectedAID = key.AID()
		_, err := verifyOptedOut("POST", urlQuery, request.Headers, o)
		isInvalidOptions(t, err)
	})

	t.Run("a minimum below the profile's is ErrInvalidOptions on both sides", func(t *testing.T) {
		_, err := verifyOptedOut("POST", urlQuery, request.Headers, VerifyOptions{Minimum: []string{"@method"}})
		isInvalidOptions(t, err)
		_, err = SignRequest(key, "POST", urlQuery, nil, SignOptions{Minimum: []string{"@method", "@path"}})
		isInvalidOptions(t, err)
		_, err = SignRequest(key, "POST", urlQuery, nil, SignOptions{Minimum: []string{`"@method`}})
		if kindOf(t, err) != KindUnsupportedComponent {
			t.Error("an unreadable minimum spec is UnsupportedComponent")
		}
		if _, err := SignRequest(key, "POST", urlQuery, nil, SignOptions{Covered: []string{`"@method" x`}}); kindOf(t, err) != KindUnsupportedComponent {
			t.Error("an unreadable covered spec is UnsupportedComponent")
		}
	})

	t.Run("an empty keyid is MissingKey", func(t *testing.T) {
		headers := map[string]string{"Signature-Input": `sig=("@method");keyid=""`, "Signature": zeroSignature}
		_, err := verifyOptedOut("GET", urlQuery, headers, VerifyOptions{})
		if kindOf(t, err) != KindMissingKey {
			t.Error("expected MissingKey")
		}
	})

	t.Run("a raw keyid is decoded strictly", func(t *testing.T) {
		// Non-zero trailing bits, and a padded spelling: neither is the key's own encoding.
		for _, keyid := range []string{key.Keyid()[:42] + "B", key.Keyid()[:41] + "=="} {
			headers := map[string]string{"Signature-Input": `sig=("@method");keyid="` + keyid + `"`, "Signature": zeroSignature}
			_, err := verifyOptedOut("GET", urlQuery, headers, VerifyOptions{})
			if kindOf(t, err) != KindMalformedKey {
				t.Errorf("%q should be MalformedKey", keyid)
			}
		}
	})
}

func TestSignatureInputRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		input   string
		minimum []string
		want    string
	}{
		"a member that is not an inner list":       {`sig=1`, nil, KindMalformedSignatureInput},
		"a covered component that is not a string": {`sig=(1);keyid="k"`, nil, KindMalformedSignatureInput},
		"an uppercase field name":                  {`sig=("Content-Type");keyid="k"`, nil, KindMalformedSignatureInput},
		"no created under a minimum":               {`sig=("@method" "@path" "@query");keyid="k"`, RequestMinimum, KindMalformedSignatureInput},
		"an integer parameter that is not one":     {`sig=("@method");created="1";keyid="k"`, nil, KindMalformedSignatureInput},
		"a string parameter that is a token":       {`sig=("@method");alg=ed25519;keyid="k"`, nil, KindMalformedSignatureInput},
		"an unknown parameter":                     {`sig=("@method");keyid="k";context="x"`, nil, KindMalformedSignatureInput},
		"a component with an unknown parameter":    {`sig=("@method";sf);keyid="k"`, nil, KindUnsupportedComponent},
		"a component with a token parameter":       {`sig=("@method";key=x);keyid="k"`, nil, KindUnsupportedComponent},
		"req in a request":                         {`sig=("@method";req);keyid="k"`, nil, KindUnsupportedComponent},
		"@status in a request":                     {`sig=("@status");keyid="k"`, nil, KindUnsupportedComponent},
		"a duplicate whatever its parameter order": {`sig=("@method" "@method");keyid="k"`, nil, KindDuplicateComponent},
	} {
		t.Run(name, func(t *testing.T) {
			headers := map[string]string{"Signature-Input": c.input, "Signature": zeroSignature}
			_, err := verifyOptedOut("GET", urlQuery, headers, VerifyOptions{Minimum: c.minimum})
			if got := kindOf(t, err); got != c.want {
				t.Errorf("kind = %s, want %s", got, c.want)
			}
		})
	}

	t.Run("in a response, a request component needs req and req must be true", func(t *testing.T) {
		for _, input := range []string{`sig=("@path");keyid="k"`, `sig=("@path";req=?0);keyid="k"`, `sig=("@status";req);keyid="k"`, `sig=("@path";req;sf);keyid="k"`} {
			headers := map[string]string{"Signature-Input": input, "Signature": zeroSignature}
			_, err := verifyResponseOptedOut(200, nil, headers, VerifyOptions{})
			if kindOf(t, err) != KindUnsupportedComponent {
				t.Errorf("%s should be UnsupportedComponent", input)
			}
		}
		items := []componentID{
			{Name: "@path", Params: []param{{Key: "req", Value: true}, {Key: "x", Value: int64(1)}}},
			{Name: "@path", Params: []param{{Key: "x", Value: int64(1)}, {Key: "req", Value: true}}},
		}
		if err := checkCovered(items, true); kindOf(t, err) != KindDuplicateComponent {
			t.Error("parameter order should not make two components different")
		}
	})
}

func TestTheWireAndTheURLAsSent(t *testing.T) {
	line := func(t *testing.T, component, rawURL string) (string, error) {
		t.Helper()
		base, err := SignatureBase("GET", rawURL, nil, []string{component}, SignatureParams{Created: 1, Keyid: "k"})
		return strings.Split(string(base), "\n")[0], err
	}
	for name, c := range map[string]struct{ component, url, want string }{
		"a path is not decoded":                                     {"@path", "https://example.com/a%7Eb/%2F", `"@path": /a%7Eb/%2F`},
		"an IP literal keeps its brackets and a non-default port":   {"@authority", "http://[::1]:8080/", `"@authority": [::1]:8080`},
		"an IP literal keeps its brackets with no port":             {"@authority", "http://[::1]/", `"@authority": [::1]`},
		"an empty port is no port":                                  {"@authority", "http://example.com:/", `"@authority": example.com`},
		"a leading double slash is origin-form, all of it the path": {"@path", "//evil.example/p?a", `"@path": //evil.example/p`},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := line(t, c.component, c.url)
			if err != nil || got != c.want {
				t.Errorf("got %q (%v), want %q", got, err, c.want)
			}
		})
	}
	// Userinfo, even an empty one, is refused rather than stripped (RFC 9110 section 4.2.4, this.i
	// @524c8qgv); 0.8 read "https://user:pw@Host.example:443/" as host.example.
	for _, rawURL := range []string{"https://example.com:http/", "https://example.com:99999/", "https://example.com:-1/", "http://[::1/", "http://::1]/",
		"https://user:pw@Host.example:443/", "https://@example.com/", "https://:@example.com/"} {
		_, err := line(t, "@authority", rawURL)
		isInvalidOptions(t, err)
	}
	// Format 3 (@524c8qgv): a target that is neither origin-form nor scheme://authority, that
	// carries a fragment, or that holds a space or a control anywhere is not read leniently, as
	// these four once were, but is the signer's mistake.
	for _, rawURL := range []string{"ht_tp://x/p", "://nonsense", "https://example.com/p?a=1#frag", " \thttps://example.com/a\nb"} {
		_, err := line(t, "@path", rawURL)
		isInvalidOptions(t, err)
	}
	if _, err := line(t, "x-note", "https://example.com/"); kindOf(t, err) != KindMissingComponent {
		t.Error("an absent field is MissingComponent")
	}
	_, err := SignatureBase("GET", "https://example.com/", map[string]string{"X-Note": "café"}, []string{"x-note"}, SignatureParams{Created: 1})
	if kindOf(t, err) != KindSignatureMismatch {
		t.Error("a non-ASCII value has no base both sides agree on")
	}
	if _, err := SignatureBase("GET", "https://example.com/", nil, []string{`"@path`}, SignatureParams{Created: 1}); kindOf(t, err) != KindUnsupportedComponent {
		t.Error("an unreadable spec is UnsupportedComponent")
	}
}

func TestCanonicalAIDSpellings(t *testing.T) {
	if _, err := VerifyingKey(paddingBitAlias(seedAID)); kindOf(t, err) != KindMalformedKey {
		t.Error("a padding-bit alias of an AID is not an AID")
	}
	for keyid, want := range map[string]bool{
		keriAID:                       false,
		paddingBitAlias(keriAID):      true,
		"D" + strings.Repeat("!", 43): true,
		"A" + strings.Repeat("A", 43): false,
		"short":                       false,
	} {
		if misspelledAID(keyid) != want {
			t.Errorf("misspelledAID(%q) = %v", keyid, !want)
		}
	}
}

func TestStructuredFieldsBeyondTheSubsetFikiActsOn(t *testing.T) {
	for text, want := range map[string]any{
		"a=1.5":     sfDecimal("1.5"),
		"a=-12.125": sfDecimal("-12.125"),
		"a=abc":     sfToken("abc"),
		"a=*x/y:z":  sfToken("*x/y:z"),
		"a=Tok":     sfToken("Tok"),
	} {
		_, parsed, err := parseDictionary(text)
		if err != nil || parsed["a"].Value != want {
			t.Errorf("%q parsed as %#v (%v)", text, parsed["a"].Value, err)
		}
	}
	for _, text := range []string{"a=1.", "a=1.2345", "a=1234567890123.5", "a=1234567890123456", `a=("m";9)`} {
		if _, _, err := parseDictionary(text); err == nil {
			t.Errorf("%q should be refused", text)
		}
	}
	_, parsed, err := parseDictionary(`a=("m";x=1;x=2)`)
	if err != nil || len(parsed["a"].List.Items[0].Params) != 1 || parsed["a"].List.Items[0].Params[0].Value != int64(2) {
		t.Errorf("a duplicated parameter overwrites the first: %+v (%v)", parsed["a"], err)
	}
	for value, want := range map[any]string{sfToken("t"): "t", sfDecimal("1.5"): "1.5", true: "?1", false: "?0"} {
		if got := serializeBareItem(value); got != want {
			t.Errorf("serializeBareItem(%#v) = %q", value, got)
		}
	}
	if got := serializeBareItem([]byte{1, 2, 3}); got != ":AQID:" {
		t.Errorf("a byte sequence serializes as %q", got)
	}
	defer func() {
		if recover() == nil {
			t.Error("a value of no RFC 8941 type should panic, as a bug in fiki")
		}
	}()
	serializeBareItem(3.5)
}

// Supplying Authorities makes @authority required (@605z9tnw, tick 7zde).
func TestSuppliedAuthoritiesRequireAuthority(t *testing.T) {
	key := testKey(t)
	sign := func(url string, covered []string) map[string]string {
		t.Helper()
		headers, err := SignRequest(key, "GET", url, nil,
			SignOptions{Covered: covered, Created: signedAt, Keyid: keriAID, Minimum: RequestMinimum})
		if err != nil {
			t.Fatal(err)
		}
		return headers
	}
	minimumOnly := append([]string(nil), RequestMinimum...)
	withAuthority := append(append([]string(nil), RequestMinimum...), "@authority")

	t.Run("a request signed for another host without @authority is refused, the cross-host replay", func(t *testing.T) {
		headers := sign("https://attacker.example/identifiers?type=rot", minimumOnly)
		_, err := verifyOptedOut("GET", "https://victim.example/identifiers?type=rot", headers, VerifyOptions{
			Resolve: resolverFor(key), Minimum: RequestMinimum, Authorities: []string{"victim.example"},
		})
		if kindOf(t, err) != KindInsufficientCoverage {
			t.Fatal("expected InsufficientCoverage")
		}
		var fikiErr *Error
		if errors.As(err, &fikiErr); fikiErr.Component != "@authority" {
			t.Errorf("the refusal names %q, not @authority", fikiErr.Component)
		}
	})

	t.Run("with AnyAuthority an uncovered @authority still verifies", func(t *testing.T) {
		headers := sign("https://victim.example/identifiers", minimumOnly)
		if _, err := verifyOptedOut("GET", "https://victim.example/identifiers", headers,
			VerifyOptions{Resolve: resolverFor(key), Minimum: RequestMinimum}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("the coverage refusal comes before the key is resolved", func(t *testing.T) {
		headers := sign("https://victim.example/identifiers", minimumOnly)
		unknown := func(string) ([]byte, error) { return nil, nil }
		_, err := verifyOptedOut("GET", "https://victim.example/identifiers", headers,
			VerifyOptions{Resolve: unknown, Authorities: []string{"victim.example"}})
		if kindOf(t, err) != KindInsufficientCoverage {
			t.Error("expected InsufficientCoverage")
		}
	})

	t.Run("a covered @authority verifies for the right host and not the wrong one", func(t *testing.T) {
		headers := sign("https://victim.example/identifiers", withAuthority)
		opts := VerifyOptions{Resolve: resolverFor(key), Authorities: []string{"victim.example"}}
		if _, err := verifyOptedOut("GET", "https://victim.example/identifiers", headers, opts); err != nil {
			t.Fatal(err)
		}
		opts.Authorities = []string{"attacker.example"}
		_, err := verifyOptedOut("GET", "https://victim.example/identifiers", headers, opts)
		if kindOf(t, err) != KindSignatureMismatch {
			t.Error("expected SignatureMismatch")
		}
	})
}

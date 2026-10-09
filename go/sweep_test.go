package fiki

// The 0.8.0 cross-port sweep (`this.i` @5zrf8gjk): the rules no vector can pin, because they are
// API behaviour — a caller's mistakes, exported names, and arithmetic a vector cannot reach.

import (
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"math"
	"strings"
	"testing"
)

// A4: two spellings of one header name are the caller's mistake on every path a mapping enters.
func TestTwoSpellingsOfOneHeaderAreTheCallersMistake(t *testing.T) {
	key := testKey(t)
	twice := map[string]string{"X-Role": "a", "x-role": "b"}
	_, err := SignRequest(key, "GET", urlQuery, twice, SignOptions{})
	isInvalidOptions(t, err)
	_, err = verifyOptedOut("GET", urlQuery, twice, VerifyOptions{})
	isInvalidOptions(t, err)
	_, err = SignResponse(key, 200, &Request{Method: "GET", URL: urlQuery, Headers: twice}, nil, SignOptions{})
	isInvalidOptions(t, err)
	_, err = verifyResponseOptedOut(200, &Request{Method: "GET", URL: urlQuery, Headers: twice}, nil, VerifyOptions{})
	isInvalidOptions(t, err)
}

// A6: a long covered list is checked in linear time, not by comparing every pair.
func TestALongCoveredListIsCheckedInLinearTime(t *testing.T) {
	scalesLinearly(t, 4000, func(n int) func() {
		headers := map[string]string{}
		covered := make([]string, 0, n)
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("x-h%d", i)
			headers[name] = "v"
			covered = append(covered, name)
		}
		return func() {
			if _, err := SignatureBase("GET", urlQuery, headers, covered, SignatureParams{Created: 1}); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// A7 and E5: a supplied Content-Digest the signer would sign as given must be one a verifier
// accepts for the body, or the call is the mistake.
func TestASuppliedDigestTheBodyDoesNotSupportIsTheCallersMistake(t *testing.T) {
	key := testKey(t)
	for name, digest := range map[string]string{
		"contradicted":       ContentDigest([]byte("another body")),
		"unparsable":         "(((",
		"no known algorithm": "sha-1=:AAAA:",
	} {
		t.Run(name, func(t *testing.T) {
			supplied := map[string]string{"Content-Digest": digest}
			_, err := SignRequest(key, "POST", urlQuery, supplied, SignOptions{Body: testBody})
			isInvalidOptions(t, err)
			_, err = SignResponse(key, 200, nil, supplied, SignOptions{Body: testBody})
			isInvalidOptions(t, err)
		})
	}
	matching := map[string]string{"Content-Digest": ContentDigest(testBody)}
	if _, err := SignRequest(key, "POST", urlQuery, matching, SignOptions{Body: testBody}); err != nil {
		t.Errorf("a digest the body matches is signed: %v", err)
	}
}

// A9: names a JavaScript object would inherit are ordinary names here, and Go's maps have no
// inherited members to reach, so this pins the analogue rather than a defence.
func TestInheritedMemberNamesAreOrdinaryNames(t *testing.T) {
	key := testKey(t)
	headers := map[string]string{"__proto__": "p", "constructor": "c", "Content-Digest": ContentDigest(testBody) + ", constructor=:AAAA:"}
	signed, err := SignRequest(key, "POST", urlQuery, headers,
		SignOptions{Body: testBody, Created: signedAt, Covered: []string{"@method", "__proto__", "constructor", "content-digest"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyOptedOut("POST", urlQuery, merged(headers, signed), VerifyOptions{Body: testBody}); err != nil {
		t.Errorf("expected a verdict, got %v", err)
	}
}

// B13: the method is an RFC 9110 token wherever a request message is built, covered or not.
func TestTheMethodIsAToken(t *testing.T) {
	key := testKey(t)
	signed, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{Created: signedAt, Covered: []string{"@path"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET X", "GE\r\nT", "(GET)", "GÉT", "GET\t"} {
		t.Run(method, func(t *testing.T) {
			_, err := SignRequest(key, method, urlQuery, nil, SignOptions{})
			isInvalidOptions(t, err)
			_, err = SignatureBase(method, urlQuery, nil, []string{"@path"}, SignatureParams{Created: 1})
			isInvalidOptions(t, err)
			_, err = verifyOptedOut(method, urlQuery, signed, VerifyOptions{})
			isInvalidOptions(t, err)
			_, err = ResponseSignatureBase(200, &Request{Method: method, URL: urlQuery}, nil, []string{"@status"}, SignatureParams{Created: 1})
			isInvalidOptions(t, err)
		})
	}
	base, err := SignatureBase("M-Search", urlQuery, nil, []string{"@method"}, SignatureParams{Created: 1})
	if err != nil || !strings.HasPrefix(string(base), `"@method": M-Search`) {
		t.Errorf("an extension method is kept as given: %q, %v", base, err)
	}
}

// B14 on the signing side: a URL whose authority cannot be read is the caller's mistake.
func TestAnUnreadableAuthorityIsTheSignersMistake(t *testing.T) {
	key := testKey(t)
	for _, rawURL := range []string{"https://example.com:65536/", "https://example.com:44x/",
		"https://[::1]x/", "http://[::1/", "http://::1]/"} {
		t.Run(rawURL, func(t *testing.T) {
			_, err := SignRequest(key, "GET", rawURL, nil, SignOptions{})
			isInvalidOptions(t, err)
			_, err = SignatureBase("GET", rawURL, nil, []string{"@authority"}, SignatureParams{Created: 1})
			isInvalidOptions(t, err)
			_, err = SignResponse(key, 200, &Request{Method: "GET", URL: rawURL}, nil,
				SignOptions{Covered: []string{"@status", Req("@authority")}})
			isInvalidOptions(t, err)
		})
	}
	// E1: read lazily, so a request whose base needs no authority is not refused for its port.
	uncovered := []string{"@method", "@path", "@query"}
	signed, err := SignRequest(key, "GET", "https://example.com:65536/x", nil, SignOptions{Created: signedAt, Covered: uncovered})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyOptedOut("GET", "https://example.com:65536/x", signed, VerifyOptions{}); err != nil {
		t.Errorf("an uncovered authority is not read: %v", err)
	}
	// And a received one is a base that cannot be built.
	_, err = verifyResponseOptedOut(200, &Request{Method: "GET", URL: "https://example.com:65536/"},
		map[string]string{"Signature-Input": `sig=("@authority";req);keyid="k"`, "Signature": zeroSignature},
		VerifyOptions{ExpectedAID: String(seedAID)})
	if kindOf(t, err) != KindSignatureMismatch {
		t.Errorf("expected SignatureMismatch, got %v", err)
	}
}

// B15: what the signer serializes must be serializable, or the call is the mistake.
func TestWhatTheSignerSerializesMustBeSerializable(t *testing.T) {
	key := testKey(t)
	for name, opts := range map[string]SignOptions{
		"label with a capital":    {Label: "Sig"},
		"label led by a digit":    {Label: "1sig"},
		"label with a space":      {Label: "s ig"},
		"label with a line break": {Label: "sig\r\nx"},
		"keyid with a line break": {Keyid: "k\r\nX-Injected: 1"},
		"nonce with DEL":          {Nonce: "n\x7f"},
		"tag outside ASCII":       {Tag: "café"},
		"component with a space":  {Covered: []string{"@method", "x role"}},
		"component line break":    {Covered: []string{"@method", "x-role\r\nx"}},
		"serialized non-token":    {Covered: []string{"@method", `"x role"`}},
		"created negative":        {Created: -1},
		"created of 16 digits":    {Created: 1_000_000_000_000_000},
		"expires negative":        {Expires: -1},
		"expires of 16 digits":    {Expires: 1_000_000_000_000_000},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := SignRequest(key, "GET", urlQuery, map[string]string{"X-Role": "r"}, opts)
			isInvalidOptions(t, err)
			_, err = SignResponse(key, 200, nil, map[string]string{"X-Role": "r"}, opts)
			isInvalidOptions(t, err)
		})
	}
	for name, params := range map[string]SignatureParams{
		"keyid": {Created: 1, Keyid: "k\n"}, "alg": {Created: 1, Alg: "ed\x00"},
		"nonce": {Created: 1, Nonce: "\t"}, "tag": {Created: 1, Tag: "é"},
		"created": {Created: -5}, "expires": {Created: 1, Expires: 1e15},
	} {
		t.Run("base "+name, func(t *testing.T) {
			_, err := SignatureBase("GET", urlQuery, nil, []string{"@method"}, params)
			isInvalidOptions(t, err)
			_, err = ResponseSignatureBase(200, nil, nil, []string{"@status"}, params)
			isInvalidOptions(t, err)
		})
	}
	headers, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{Label: "*a1_.-*", Keyid: "~ !",
		Nonce: " ", Tag: "~", Created: 999_999_999_999_999, Expires: 999_999_999_999_999})
	if err != nil || !strings.HasPrefix(headers["Signature-Input"], "*a1_.-*=") {
		t.Errorf("the edges of each range are signed: %v, %v", headers, err)
	}
	// A derived component fiki does not build stays UnsupportedComponent (E6).
	if _, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{Covered: []string{"@target-uri"}}); kindOf(t, err) != KindUnsupportedComponent {
		t.Error("expected UnsupportedComponent")
	}
}

// B17: a freshness window, when given, is a positive number of seconds, and a large one cannot
// overflow into a refusal.
func TestAFreshnessWindowIsPositiveAndSaturates(t *testing.T) {
	headers, _ := sign(t, SignOptions{Expires: signedAt + 1})
	unexpiring, _ := sign(t, SignOptions{})
	for name, opts := range map[string]VerifyOptions{
		"max_age zero":     {MaxAge: maxAge(0)},
		"max_age negative": {MaxAge: maxAge(-1)},
		"skew zero":        {Skew: maxAge(0)},
		"skew negative":    {Skew: maxAge(-60)},
	} {
		t.Run(name, func(t *testing.T) {
			opts.Body = testBody
			_, err := verifyOptedOut("POST", urlQuery, headers, opts)
			isInvalidOptions(t, err)
			_, err = verifyResponseOptedOut(200, nil, headers, opts)
			isInvalidOptions(t, err)
		})
	}
	late := signedAt + 1_000_000
	for name, c := range map[string]struct {
		headers map[string]string
		opts    VerifyOptions
	}{
		"max_age at the top":  {unexpiring, VerifyOptions{MaxAge: maxAge(math.MaxInt64), Now: late}},
		"skew at the top":     {headers, VerifyOptions{MaxAge: maxAge(1), Skew: maxAge(math.MaxInt64), Now: late}},
		"both at the top":     {headers, VerifyOptions{MaxAge: maxAge(math.MaxInt64), Skew: maxAge(math.MaxInt64), Now: late}},
		"declined, wide skew": {headers, VerifyOptions{Skew: maxAge(math.MaxInt64), Now: late}},
	} {
		t.Run(name, func(t *testing.T) {
			opts := c.opts
			opts.Body = testBody
			if _, err := verifyOptedOut("POST", urlQuery, c.headers, opts); err != nil {
				t.Errorf("expected a verdict, got %v", err)
			}
		})
	}
	future, _ := sign(t, SignOptions{Created: 999_999_999_999_999})
	_, err := verifyOptedOut("POST", urlQuery, future, VerifyOptions{Body: testBody, MaxAge: maxAge(60), Now: math.MinInt64})
	if kindOf(t, err) != KindSignatureTooOld {
		t.Errorf("a created far after now is too far in the future, got %v", err)
	}
}

// B18: Verdict.Keyid is the wire keyid, empty when there was none; AID is who vouched.
func TestTheVerdictReportsTheWireKeyidAndWhoVouched(t *testing.T) {
	key := testKey(t)
	headers, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{Created: signedAt, Keyid: "claimed"})
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := verifyOptedOut("GET", urlQuery, headers, VerifyOptions{ExpectedAID: String(key.AID())})
	if err != nil || verdict.Keyid != "claimed" || verdict.AID != key.AID() {
		t.Errorf("verdict %+v, %v", verdict, err)
	}
	base, err := SignatureBase("GET", urlQuery, nil, DefaultCovered, SignatureParams{Created: signedAt, Alg: Alg})
	if err != nil {
		t.Fatal(err)
	}
	params := string(base)[strings.LastIndex(string(base), `"@signature-params": `)+len(`"@signature-params": `):]
	unnamed := map[string]string{"Signature-Input": "sig=" + params, "Signature": "sig=:" + b64std(key.Sign(base)) + ":"}
	verdict, err = verifyOptedOut("GET", urlQuery, unnamed, VerifyOptions{ExpectedAID: String(key.AID())})
	if err != nil || verdict.Keyid != "" || verdict.AID != key.AID() {
		t.Errorf("verdict %+v, %v", verdict, err)
	}

	// And the doc comment says so, since the field's meaning is the contract.
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, "messages.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := doc.NewFromFiles(files, []*ast.File{parsed}, "github.com/bakobo/fiki/go")
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range pkg.Types {
		if typ.Name != "Verdict" {
			continue
		}
		text := strings.Join(strings.Fields(typ.Doc), " ")
		for _, want := range []string{"exactly as it appeared on the wire", "empty when the signature had none", "the identity that vouched for the key"} {
			if !strings.Contains(text, want) {
				t.Errorf("Verdict's doc comment does not say %q", want)
			}
		}
		return
	}
	t.Fatal("no Verdict type documented in messages.go")
}

// B19 and E3: both vectors formats and the four bounds are exported.
func TestTheFormatsAndBoundsAreExported(t *testing.T) {
	if VectorsFormat != 3 || KeriVectorsFormat != 5 {
		t.Errorf("formats %d and %d", VectorsFormat, KeriVectorsFormat)
	}
	if MaxFieldBytes != 8192 || MaxDictionaryMembers != 16 || MaxInnerListItems != 64 || MaxParameters != 16 {
		t.Errorf("bounds %d %d %d %d", MaxFieldBytes, MaxDictionaryMembers, MaxInnerListItems, MaxParameters)
	}
}

// A10: a keyid other than the expected one is refused without asking the resolver.
func TestAnUnexpectedKeyidNeverReachesTheResolver(t *testing.T) {
	key := testKey(t)
	headers, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{Created: signedAt, Keyid: keriAID})
	if err != nil {
		t.Fatal(err)
	}
	asked := 0
	resolve := func(string) ([]byte, error) { asked++; return nil, nil }
	_, err = verifyOptedOut("GET", urlQuery, headers, VerifyOptions{Resolve: resolve, ExpectedKeyid: String("E" + strings.Repeat("A", 43))})
	if kindOf(t, err) != KindUnknownKey || asked != 0 {
		t.Errorf("expected UnknownKey without a resolution, got %v after %d", err, asked)
	}
}

// A3 and bakobo/fiki#14's hostile pass: what sits between an IP-literal's brackets is an IPv6
// address, with an optional zone, or IPvFuture, as Python's urlsplit checks it. The same lists as
// fiki-py's tests/test_sweep.py, whose oracle is Python's own ipaddress.
func TestAnIPLiteralHoldsAnIPv6AddressOrIPvFuture(t *testing.T) {
	key := testKey(t)
	signed, err := SignRequest(key, "GET", "https://[::1]/x", nil, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	for _, inside := range []string{"not-an-ip", "1.2.3.4", "vZ.x", "v1.", "V1.x", "v.x", "::1%",
		"fe80::1%a%b", "1:2:3:4:5:6:7:8:9", "::01.2.3.4", "::256.1.1.1", "12345::", "", "1::2::3"} {
		t.Run(inside, func(t *testing.T) {
			rawURL := "https://[" + inside + "]/x"
			_, err := SignatureBase("GET", rawURL, nil, []string{"@authority"}, SignatureParams{Created: 1})
			isInvalidOptions(t, err)
			_, err = verifyOptedOut("GET", rawURL, signed, VerifyOptions{})
			if kindOf(t, err) != KindSignatureMismatch {
				t.Errorf("received: %v", err)
			}
		})
	}
	for _, inside := range []string{"::1", "::", "1::", "2001:DB8::1", "1:2:3:4:5:6:7:8",
		"1:2:3:4:5:6:7::", "::ffff:1.2.3.4", "1:2:3:4:5:6:1.2.3.4", "fe80::1%25eth0", "v1.x",
		"vF.a:b", "v12.["} {
		base, err := SignatureBase("GET", "https://["+inside+"]/x", nil, []string{"@authority"}, SignatureParams{Created: 1})
		want := `"@authority": [` + strings.ToLower(inside) + "]\n"
		if err != nil || !strings.HasPrefix(string(base), want) {
			t.Errorf("[%s]: %q, %v", inside, base, err)
		}
	}
}

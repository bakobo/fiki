package fiki

// The ground the shared vectors do not cover: signing a fresh request, generating a key, the
// parser's own refusal branches, and the freshness rules beyond the three cases refusals.json
// pins. Those are not cross-implementation contracts — they are this port working.

import (
	"errors"
	"strings"
	"testing"
)

const (
	seedAID  = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"
	urlQuery = "https://api.example.com/things?limit=1&sort=name"
	signedAt = int64(1700000000)
)

var testBody = []byte(`{"hello": "world"}`)

func testKey(t *testing.T) *Key {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	key, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func maxAge(v int64) *int64 { return &v }

func sign(t *testing.T, opts SignOptions) (map[string]string, *Key) {
	t.Helper()
	key := testKey(t)
	if opts.Created == 0 {
		opts.Created = signedAt
	}
	headers, err := SignRequest(key, "POST", urlQuery, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	return headers, key
}

func kindOf(t *testing.T, err error) string {
	t.Helper()
	var fikiErr *Error
	if !errors.As(err, &fikiErr) {
		t.Fatalf("expected a fiki.Error, got %T: %v", err, err)
	}
	return fikiErr.Kind
}

func TestKeys(t *testing.T) {
	key := testKey(t)
	if key.AID() != seedAID {
		t.Errorf("AID = %q, want the one keripy derives for this seed", key.AID())
	}
	if len(key.Seed()) != 32 {
		t.Errorf("seed is %d bytes", len(key.Seed()))
	}
	if _, err := FromSeed(make([]byte, 31)); kindOf(t, err) != KindMalformedKey {
		t.Error("a short seed should be refused by name")
	}
	if Generate().AID() == key.AID() {
		t.Error("Generate should produce a fresh key")
	}
	if (&Error{Message: "a message"}).Error() != "a message" {
		t.Error("an Error should report its message")
	}
	if ToAID(mustKey(t, seedAID)) != seedAID {
		t.Error("the lens should round-trip")
	}
}

func mustKey(t *testing.T, aid string) []byte {
	t.Helper()
	raw, err := VerifyingKey(aid)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifyingKeyRefusals(t *testing.T) {
	for name, aid := range map[string]string{
		"too short":            "B" + strings.Repeat("A", 42),
		"too long":             "B" + strings.Repeat("A", 44),
		"transferable prefix":  "D" + strings.Repeat("A", 43),
		"outside the alphabet": "B" + strings.Repeat("!", 43),
		// "=" is inside base64's alphabet, so a lenient decoder would take this and decode short.
		"padded": "B" + strings.Repeat("A", 41) + "==",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyingKey(aid); kindOf(t, err) != KindMalformedKey {
				t.Errorf("%q should be refused as a malformed key", aid)
			}
		})
	}
}

func TestSignatureBaseComponents(t *testing.T) {
	line := func(t *testing.T, component, method, rawURL string, headers map[string]string) string {
		t.Helper()
		base, err := SignatureBase(method, rawURL, headers, []string{component},
			SignatureParams{Created: signedAt, Keyid: "k"})
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(string(base), "\n")[0]
	}

	cases := []struct {
		name, component, method, url, want string
		headers                            map[string]string
	}{
		{"authority from the host header", "@authority", "GET", "/things", `"@authority": api.example.com`, map[string]string{"Host": "API.example.com"}},
		{"default port omitted", "@authority", "GET", "https://EXAMPLE.com:443/f", `"@authority": example.com`, nil},
		{"non-default port kept", "@authority", "GET", "https://example.com:8443/f", `"@authority": example.com:8443`, nil},
		{"empty path is a slash", "@path", "GET", "https://example.com", `"@path": /`, nil},
		{"no query is a bare question mark", "@query", "GET", "https://example.com/f", `"@query": ?`, nil},
		{"percent-encoding is not decoded", "@query", "GET", "https://example.com/p?baz=bat%2Dman", `"@query": ?baz=bat%2Dman`, nil},
		{"method is uppercased", "@method", "post", "https://example.com/f", `"@method": POST`, nil},
		{"header names are lowercased and values trimmed", "Content-Type", "GET", "https://example.com/f", `"content-type": application/json`, map[string]string{"Content-Type": "  application/json  "}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := line(t, c.component, c.method, c.url, c.headers); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}

	t.Run("an unbuildable derived component is refused, not skipped", func(t *testing.T) {
		_, err := SignatureBase("GET", "https://example.com/f", nil, []string{"@target-uri"}, SignatureParams{Created: 1, Keyid: "k"})
		if kindOf(t, err) != KindUnsupportedComponent {
			t.Error("expected UnsupportedComponent")
		}
	})
	t.Run("a covered header the request lacks is refused", func(t *testing.T) {
		_, err := SignatureBase("GET", "https://example.com/f", nil, []string{"x-absent"}, SignatureParams{Created: 1, Keyid: "k"})
		if kindOf(t, err) != KindMissingComponent {
			t.Error("expected MissingComponent")
		}
	})
	t.Run("authority with no url authority and no host header is refused", func(t *testing.T) {
		_, err := SignatureBase("GET", "/things", nil, []string{"@authority"}, SignatureParams{Created: 1, Keyid: "k"})
		if kindOf(t, err) != KindMissingComponent {
			t.Error("expected MissingComponent")
		}
	})
	t.Run("an unparsable url is refused", func(t *testing.T) {
		_, err := SignatureBase("GET", "://nonsense", nil, []string{"@path"}, SignatureParams{Created: 1, Keyid: "k"})
		if err == nil {
			t.Error("expected a refusal")
		}
	})
	t.Run("optional parameters serialize in a fixed order", func(t *testing.T) {
		base, err := SignatureBase("GET", "https://example.com/f", nil, []string{"@method"},
			SignatureParams{Created: signedAt, Keyid: "k", Alg: "ed25519", Expires: signedAt + 60, Nonce: "abc", Tag: "app"})
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(base), "\n")
		want := `"@signature-params": ("@method");created=1700000000;expires=1700000060;nonce="abc";alg="ed25519";keyid="k";tag="app"`
		if lines[len(lines)-1] != want {
			t.Errorf("got %q, want %q", lines[len(lines)-1], want)
		}
	})
}

func TestSignAndVerify(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		headers, key := sign(t, SignOptions{Body: testBody})
		verdict, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{Body: testBody})
		if err != nil {
			t.Fatal(err)
		}
		if verdict.AID != key.AID() {
			t.Errorf("AID = %q", verdict.AID)
		}
	})

	t.Run("a body is digested and covered", func(t *testing.T) {
		headers, _ := sign(t, SignOptions{Body: testBody})
		if headers["Content-Digest"] == "" {
			t.Fatal("no Content-Digest returned")
		}
	})

	t.Run("a caller-supplied digest is used rather than recomputed", func(t *testing.T) {
		key := testKey(t)
		supplied := map[string]string{"Content-Digest": ContentDigest(testBody)}
		out, err := SignRequest(key, "POST", urlQuery, supplied, SignOptions{Body: testBody, Created: signedAt})
		if err != nil {
			t.Fatal(err)
		}
		if _, echoed := out["Content-Digest"]; echoed {
			t.Error("fiki should not echo back a digest the caller already sent")
		}
		headers := map[string]string{"Content-Digest": supplied["Content-Digest"]}
		for k, v := range out {
			headers[k] = v
		}
		if _, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{Body: testBody}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a chosen covered set omitting the digest refuses a body", func(t *testing.T) {
		key := testKey(t)
		_, err := SignRequest(key, "POST", urlQuery, nil, SignOptions{Body: testBody, Covered: []string{"@method"}})
		if kindOf(t, err) != KindUncoveredBody {
			t.Error("expected UncoveredBody")
		}
	})

	t.Run("a chosen covered set including the digest signs a body", func(t *testing.T) {
		key := testKey(t)
		headers, err := SignRequest(key, "POST", urlQuery, nil,
			SignOptions{Body: testBody, Covered: []string{"@method", "@path", "content-digest"}, Created: signedAt, Label: "mine"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(headers["Signature-Input"], "mine=") {
			t.Error("the label should be the one asked for")
		}
		if _, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{Body: testBody}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("signing without a created uses the wall clock", func(t *testing.T) {
		key := testKey(t)
		headers, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRequest("GET", urlQuery, headers, VerifyOptions{MaxAge: maxAge(300)}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("an expected AID is authoritative over the inline keyid", func(t *testing.T) {
		headers, key := sign(t, SignOptions{})
		if _, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{ExpectedAID: key.AID()}); err != nil {
			t.Fatal(err)
		}
		other := Generate()
		_, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{ExpectedAID: other.AID()})
		if kindOf(t, err) != KindSignatureMismatch {
			t.Error("a stranger's AID should not verify")
		}
	})

	t.Run("a malformed expected AID is refused", func(t *testing.T) {
		headers, _ := sign(t, SignOptions{})
		_, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{ExpectedAID: "nope"})
		if kindOf(t, err) != KindMalformedKey {
			t.Error("expected MalformedKey")
		}
	})

	t.Run("a covered component the verifier cannot build is refused", func(t *testing.T) {
		headers, _ := sign(t, SignOptions{})
		headers["Signature-Input"] = strings.Replace(headers["Signature-Input"], `("@method"`, `("@target-uri"`, 1)
		_, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{})
		if kindOf(t, err) != KindUnsupportedComponent {
			t.Error("expected UnsupportedComponent")
		}
	})

	t.Run("a digest naming an unknown algorithm alongside a known one verifies", func(t *testing.T) {
		key := testKey(t)
		supplied := map[string]string{"Content-Digest": "sha-1=:AAAA:, " + ContentDigest(testBody)}
		out, err := SignRequest(key, "POST", urlQuery, supplied, SignOptions{Body: testBody, Created: signedAt})
		if err != nil {
			t.Fatal(err)
		}
		headers := map[string]string{"Content-Digest": supplied["Content-Digest"]}
		for k, v := range out {
			headers[k] = v
		}
		if _, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{Body: testBody}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a digest value that is not a byte sequence is refused", func(t *testing.T) {
		key := testKey(t)
		supplied := map[string]string{"Content-Digest": `sha-256="not bytes"`}
		out, err := SignRequest(key, "POST", urlQuery, supplied, SignOptions{Body: testBody, Created: signedAt})
		if err != nil {
			t.Fatal(err)
		}
		headers := map[string]string{"Content-Digest": supplied["Content-Digest"]}
		for k, v := range out {
			headers[k] = v
		}
		_, err = VerifyRequest("POST", urlQuery, headers, VerifyOptions{Body: testBody})
		if kindOf(t, err) != KindMalformedDigest {
			t.Error("expected MalformedDigest")
		}
	})
}

func TestSignAndVerifyRefusals(t *testing.T) {
	t.Run("signing against an unparsable url is refused", func(t *testing.T) {
		key := testKey(t)
		if _, err := SignRequest(key, "GET", "://nonsense", nil, SignOptions{}); err == nil {
			t.Error("expected a refusal")
		}
	})

	t.Run("an unparsable Content-Digest is refused", func(t *testing.T) {
		key := testKey(t)
		supplied := map[string]string{"Content-Digest": "((( not sfv"}
		out, err := SignRequest(key, "POST", urlQuery, supplied, SignOptions{Body: testBody, Created: signedAt})
		if err != nil {
			t.Fatal(err)
		}
		headers := map[string]string{"Content-Digest": supplied["Content-Digest"]}
		for k, v := range out {
			headers[k] = v
		}
		if _, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{Body: testBody}); kindOf(t, err) != KindMalformedDigest {
			t.Error("expected MalformedDigest")
		}
	})

	t.Run("a sha-512 digest is computed and compared", func(t *testing.T) {
		// The other algorithm RFC 9530 names. fiki emits sha-256 and accepts either on the way in,
		// because it is not the only thing that will ever have signed a request it verifies.
		key := testKey(t)
		sum := digestAlgorithms["sha-512"](testBody)
		supplied := map[string]string{"Content-Digest": "sha-512=:" + b64std(sum) + ":"}
		out, err := SignRequest(key, "POST", urlQuery, supplied, SignOptions{Body: testBody, Created: signedAt})
		if err != nil {
			t.Fatal(err)
		}
		headers := map[string]string{"Content-Digest": supplied["Content-Digest"]}
		for k, v := range out {
			headers[k] = v
		}
		if _, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{Body: testBody}); err != nil {
			t.Fatalf("a sha-512 digest should verify: %v", err)
		}
	})
}

func TestFreshness(t *testing.T) {
	inside := func(now int64, age *int64, skew *int64) error {
		headers, _ := sign(t, SignOptions{})
		_, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{MaxAge: age, Now: now, Skew: skew})
		return err
	}

	if err := inside(signedAt+299, maxAge(300), nil); err != nil {
		t.Errorf("a signature inside max age should verify: %v", err)
	}
	if err := inside(signedAt+303, maxAge(300), nil); err != nil {
		t.Errorf("skew should be tolerated: %v", err)
	}
	if err := inside(signedAt+400, maxAge(300), nil); kindOf(t, err) != KindSignatureTooOld {
		t.Error("a signature past max age should be refused")
	}
	zero := int64(0)
	if err := inside(signedAt+301, maxAge(300), &zero); kindOf(t, err) != KindSignatureTooOld {
		t.Error("the skew allowance should be adjustable")
	}
	if err := inside(signedAt-60, maxAge(300), nil); kindOf(t, err) != KindSignatureTooOld {
		t.Error("a created in the future should be refused")
	}
	if err := inside(signedAt+1000000, nil, nil); err != nil {
		t.Errorf("declining the check should decline it: %v", err)
	}

	t.Run("expires is enforced even when max age is declined", func(t *testing.T) {
		headers, _ := sign(t, SignOptions{Expires: signedAt + 60})
		if _, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{Now: signedAt + 30}); err != nil {
			t.Fatalf("before its expiry it should verify: %v", err)
		}
		_, err := VerifyRequest("POST", urlQuery, headers, VerifyOptions{Now: signedAt + 66})
		if kindOf(t, err) != KindSignatureExpired {
			t.Error("expected SignatureExpired")
		}
	})

	t.Run("a max-age check against a signature with no created is refused", func(t *testing.T) {
		// RFC 9421 makes created optional, so a foreign signer may omit it. fiki's own never does,
		// and the signature has to be genuinely made that way — freshness is checked after the
		// signature, so a doctored Signature-Input just fails the signature instead.
		key := testKey(t)
		list := innerList{Items: []string{"@method", "@path"}, Params: []param{{Key: "keyid", Value: key.Keyid()}}}
		lines, err := componentLines("GET", "/a", nil, list.Items)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, `"@signature-params": `+serializeInnerList(list))
		signature := key.Sign([]byte(strings.Join(lines, "\n")))
		headers := map[string]string{
			"Signature-Input": "sig=" + serializeInnerList(list),
			"Signature":       "sig=:" + b64std(signature) + ":",
		}
		if _, err := VerifyRequest("GET", "/a", headers, VerifyOptions{}); err != nil {
			t.Fatalf("with no policy it should verify: %v", err)
		}
		_, err = VerifyRequest("GET", "/a", headers, VerifyOptions{MaxAge: maxAge(300), Now: signedAt})
		if kindOf(t, err) != KindSignatureTooOld {
			t.Error("expected SignatureTooOld")
		}
	})
}

func TestStructuredFieldSubset(t *testing.T) {
	t.Run("round-trips what RFC 9421 puts in Signature-Input", func(t *testing.T) {
		_, parsed, err := parseDictionary(`sig=("@method" "@path");created=1;keyid="k";alg="ed25519"`)
		if err != nil {
			t.Fatal(err)
		}
		want := `("@method" "@path");created=1;keyid="k";alg="ed25519"`
		if got := serializeInnerList(parsed["sig"].List); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("reads the shapes RFC 8941 allows here", func(t *testing.T) {
		for _, text := range []string{"a=?1", "a=?0", "a=-12", "a", "a;x", `a="say \"hi\" \\"`, "a=()", "  a=1  ", "a=:AAAA:"} {
			if _, _, err := parseDictionary(text); err != nil {
				t.Errorf("%q should parse: %v", text, err)
			}
		}
	})

	t.Run("escapes on the way back out", func(t *testing.T) {
		got := serializeInnerList(innerList{
			Items:  []string{`a"b\c`},
			Params: []param{{Key: "f", Value: true}, {Key: "g", Value: false}},
		})
		if got != `("a\"b\\c");f;g=?0` {
			t.Errorf("got %q", got)
		}
	})

	for name, text := range map[string]string{
		"a key that does not start a key":          "1=2",
		"an unterminated string":                   `a="oops`,
		"a bad escape":                             `a="o\ps"`,
		"a string ending mid-escape":               `a="oops\`,
		"a byte sequence that is not base64":       "a=:not base64!:",
		"an unterminated byte sequence":            "a=:AAAA",
		"a bad boolean":                            "a=?2",
		"a truncated boolean":                      "a=?",
		"an item of no supported type":             "a=%bad",
		"an unterminated inner list":               `a=("@method"`,
		"parameters on a covered component":        `a=("@method";q=1)`,
		"a non-string covered component":           "a=(1)",
		"a missing separator inside an inner list": `a=("@method""@path")`,
		"a missing comma between members":          "a=1 b=2",
		"a trailing comma":                         "a=1, ",
		"an integer that is not one":               "a=-",
		"a parameter key that is not one":          "a=1;9",
		"a parameter value of no supported type":   "a=1;x=%",
		"an inner list parameter of no type":       `a=("m");x=%`,
		"an item of no type inside an inner list":  "a=(%)",
		"a member value that runs off the end":     "a=",
		"a bare member with a bad parameter":       "a;x=%",
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			if _, _, err := parseDictionary(text); err == nil {
				t.Errorf("%q should be refused", text)
			}
		})
	}
}

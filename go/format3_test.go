package fiki

// Vectors format 3's policy (this.i @524c8qgv), where the shared vectors cannot reach: the shape of
// Go's options, and the authority rules on the signing side.

import (
	"strconv"
	"strings"
	"testing"
)

func TestTheFormat3Policy(t *testing.T) {
	key := testKey(t)
	// Signed over the profile's minimum, which leaves out @authority.
	headers, err := SignRequest(key, "GET", urlQuery, nil, SignOptions{Created: signedAt, Covered: RequestMinimum})
	if err != nil {
		t.Fatal(err)
	}
	served := []string{"api.example.com"}

	t.Run("left unstated, the minimum is DefaultMinimum", func(t *testing.T) {
		_, err := VerifyRequest("GET", urlQuery, headers, VerifyOptions{AnyAge: true, Authorities: served})
		if kindOf(t, err) != KindInsufficientCoverage {
			t.Errorf("expected InsufficientCoverage, got %v", err)
		}
	})
	t.Run("NoMinimum and AnyAuthority opt out of both", func(t *testing.T) {
		if _, err := VerifyRequest("GET", urlQuery, headers, VerifyOptions{AnyAge: true, NoMinimum: true, AnyAuthority: true}); err != nil {
			t.Error(err)
		}
	})
	for name, opts := range map[string]VerifyOptions{
		"no decision about authorities":     {AnyAge: true},
		"both Authorities and AnyAuthority": {AnyAge: true, Authorities: served, AnyAuthority: true},
		"an empty Authorities":              {AnyAge: true, Authorities: []string{}},
		"both Minimum and NoMinimum":        {AnyAge: true, AnyAuthority: true, Minimum: RequestMinimum, NoMinimum: true},
	} {
		t.Run(name+" is the caller's mistake", func(t *testing.T) {
			_, err := VerifyRequest("GET", urlQuery, headers, opts)
			isInvalidOptions(t, err)
		})
	}

	t.Run("an ExpectedKeyid beside AnyKeyid is the caller's mistake", func(t *testing.T) {
		_, err := VerifyRequest("GET", urlQuery, headers, VerifyOptions{AnyAge: true, AnyAuthority: true, AnyKeyid: true, ExpectedKeyid: String("k")})
		isInvalidOptions(t, err)
	})

	request := &Request{Method: "GET", URL: urlQuery, Headers: headers}
	for name, opts := range map[string]VerifyOptions{
		"AnyAuthority":                    {AnyAge: true, AnyAuthority: true, AnyKeyid: true},
		"both Minimum and NoMinimum":      {AnyAge: true, Minimum: ResponseMinimum, NoMinimum: true, AnyKeyid: true},
		"no decision about the keyid":     {AnyAge: true},
		"both ExpectedKeyid and AnyKeyid": {AnyAge: true, ExpectedKeyid: String("k"), AnyKeyid: true},
	} {
		t.Run(name+" on a response is the caller's mistake", func(t *testing.T) {
			_, err := VerifyResponse(200, request, map[string]string{}, opts)
			isInvalidOptions(t, err)
		})
	}
}

func TestAnAuthorityIsCheckedAsASCIIBeforeItIsLowercased(t *testing.T) {
	// U+212A KELVIN SIGN lowercases to "k" (review A6), so a host holding it must be refused
	// rather than read as kapi.example.com.
	kelvin := "Kapi.example.com"
	base := func(rawURL string, headers map[string]string, covered ...string) (string, error) {
		raw, err := SignatureBase("GET", rawURL, headers, covered, SignatureParams{Created: 1, Keyid: "k"})
		return strings.Split(string(raw), "\n")[0], err
	}
	if _, err := base("/x", map[string]string{"Host": kelvin}, "@authority"); kindOf(t, err) != KindSignatureMismatch {
		t.Errorf("a Host holding U+212A: %v", err)
	}
	_, err := base("https://"+kelvin+"/x", nil, "@authority")
	isInvalidOptions(t, err)

	key := testKey(t)
	headers, err := SignRequest(key, "GET", "/x", map[string]string{"Host": "kapi.example.com"}, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	headers["Host"] = kelvin
	_, err = VerifyRequest("GET", "/x", headers, VerifyOptions{AnyAge: true, Authorities: []string{"kapi.example.com"}})
	if kindOf(t, err) != KindSignatureMismatch {
		t.Errorf("verifying under a Host holding U+212A: %v", err)
	}
	_, err = VerifyRequest("GET", "https://"+kelvin+"/x", headers, VerifyOptions{AnyAge: true, AnyAuthority: true})
	if kindOf(t, err) != KindSignatureMismatch {
		t.Errorf("verifying a URL whose host holds U+212A: %v", err)
	}

	for name, c := range map[string]struct {
		url, host, want string
	}{
		// Without a scheme no port is a default one, so Host keeps even 443 (this.i, "Host is
		// validated like any authority").
		"Host keeps a port of 443":                  {"/x", "Api.Example.com:443", `"@authority": api.example.com:443`},
		"Host keeps a port of 0":                    {"/x", "api.example.com:0", `"@authority": api.example.com:0`},
		"a scheme with no default port keeps 0":     {"ftp://api.example.com:0/x", "", `"@authority": api.example.com:0`},
		"an empty Host is an empty authority":       {"/x", "", `"@authority": `},
		"Host is trimmed of SP and HTAB, then read": {"/x", " \tapi.example.com\t ", `"@authority": api.example.com`},
	} {
		t.Run(name, func(t *testing.T) {
			headers := map[string]string{}
			if strings.HasPrefix(c.url, "/") {
				headers["Host"] = c.host
			}
			got, err := base(c.url, headers, "@authority")
			if err != nil || got != c.want {
				t.Errorf("got %q (%v), want %q", got, err, c.want)
			}
		})
	}
}

func TestAnUnreadableTargetIsRefusedForEveryComponentItHolds(t *testing.T) {
	for _, component := range []string{"@authority", "@path", "@query"} {
		_, err := SignatureBase("GET", "things?x", map[string]string{"Host": "a"}, []string{component}, SignatureParams{Created: 1})
		isInvalidOptions(t, err)
	}
	// A component that is not read from the target does not need one.
	if _, err := SignatureBase("GET", "things?x", nil, []string{"@method"}, SignatureParams{Created: 1}); err != nil {
		t.Error(err)
	}
}

// #17 hostile pass: DefaultMinimum is an exported slice, and VerifyRequest read it directly, so
// any code in the process could drop @authority from every default verifier's policy.
func TestChangingTheExportedDefaultMinimumChangesNoVerifier(t *testing.T) {
	saved := append([]string(nil), DefaultMinimum...)
	defer copy(DefaultMinimum, saved)
	for i := range DefaultMinimum {
		if DefaultMinimum[i] == "@authority" {
			DefaultMinimum[i] = "@method"
		}
	}
	headers, err := SignRequest(testKey(t), "GET", urlQuery, nil,
		SignOptions{Created: signedAt, Covered: RequestMinimum})
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyRequest("GET", urlQuery, headers, VerifyOptions{AnyAge: true, AnyAuthority: true})
	if kindOf(t, err) != KindInsufficientCoverage {
		t.Fatalf("want InsufficientCoverage for a signature without @authority, got %v", err)
	}
}

// The private copies fiki reads must say exactly what the exported slices document.
func TestThePrivateMinimumsMatchTheExportedOnes(t *testing.T) {
	for name, pair := range map[string][2][]string{
		"request":  {RequestMinimum, requestMinimum[:]},
		"response": {ResponseMinimum, responseMinimum[:]},
		"default":  {DefaultMinimum, defaultMinimum[:]},
	} {
		if strings.Join(pair[0], "|") != strings.Join(pair[1], "|") {
			t.Errorf("%s: exported %v, private %v", name, pair[0], pair[1])
		}
	}
}

// Format 3 part two (this.i @524c8qgv): VerifyResponse fails closed, and its keyid decision.
func TestTheFormat3ResponsePolicy(t *testing.T) {
	key := testKey(t)
	request := &Request{Method: "GET", URL: urlQuery}
	statusOnly, err := SignResponse(key, 200, nil, nil, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("left unstated, the minimum is ResponseMinimum", func(t *testing.T) {
		_, err := VerifyResponse(200, request, statusOnly, VerifyOptions{AnyAge: true, AnyKeyid: true})
		if kindOf(t, err) != KindInsufficientCoverage {
			t.Errorf("expected InsufficientCoverage, got %v", err)
		}
	})
	t.Run("NoMinimum and AnyKeyid opt out of both", func(t *testing.T) {
		verdict, err := VerifyResponse(200, request, statusOnly, VerifyOptions{AnyAge: true, NoMinimum: true, AnyKeyid: true})
		if err != nil || verdict.Keyid != key.Keyid() {
			t.Errorf("verdict %+v, err %v", verdict, err)
		}
	})
	t.Run("an ExpectedKeyid refuses any other signer", func(t *testing.T) {
		_, err := VerifyResponse(200, request, statusOnly, VerifyOptions{AnyAge: true, NoMinimum: true, ExpectedKeyid: String(keriAID)})
		if kindOf(t, err) != KindUnknownKey {
			t.Errorf("expected UnknownKey, got %v", err)
		}
	})
}

// An error quotes at most 64 characters of an untrusted value, says it was cut and how long it
// was, and escapes control characters (this.i @524c8qgv; review A9, B9). Not a vector: the
// drivers' message check pins the cap portably, and this pins Go's spelling of it.
func TestAnErrorQuotesAtMost64CharactersOfAnUntrustedValue(t *testing.T) {
	key := testKey(t)
	headers, err := SignRequest(key, "GET", "https://api.example.com/x", nil, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	long := "https://api.example.com/" + strings.Repeat("p", 9000)
	_, err = verifyOptedOut("GET", long, headers, VerifyOptions{})
	if kindOf(t, err) != KindSignatureMismatch {
		t.Fatalf("expected SignatureMismatch, got %v", err)
	}
	if len(err.Error()) > 400 || !strings.Contains(err.Error(), "(cut from 9024 characters)") ||
		!strings.Contains(err.Error(), strconv.Quote(long[:64])+" ") {
		t.Errorf("message: %s", err)
	}
	_, err = verifyOptedOut("GET", "https://api.example.com/a\x1bb", headers, VerifyOptions{})
	if strings.ContainsRune(err.Error(), 0x1b) || !strings.Contains(err.Error(), `\x1b`) {
		t.Errorf("message: %q", err)
	}
	// Cut by characters, never inside one.
	if got := shown(strings.Repeat("K", 65)); got != strconv.Quote(strings.Repeat("K", 64))+" (cut from 65 characters)" {
		t.Errorf("shown = %s", got)
	}
	if got := shown(strings.Repeat("a", 64)); got != strconv.Quote(strings.Repeat("a", 64)) {
		t.Errorf("shown = %s", got)
	}
}

// Field names fold A-Z to a-z and nothing else (this.i @524c8qgv; review A6, B5).
func TestFieldNamesFoldASCIIOnly(t *testing.T) {
	if asciiLower("X-Note") != "x-note" || asciiLower("Key") != "Key" || asciiLower("\xffA") != "\xffa" {
		t.Error("asciiLower folds more or less than A-Z")
	}
	canonical, err := canonicalHeaders(map[string]string{"Key-Id": "v", "Key-Id": "w"})
	if err != nil || canonical["key-id"] != "v" || canonical["Key-id"] != "w" {
		t.Errorf("canonical = %v, %v", canonical, err)
	}
	if Req("@PATH") != `"@path";req` {
		t.Error(Req("@PATH"))
	}
}

// Every covered value is bounded at MaxFieldBytes, inclusive, as received (this.i @524c8qgv), on
// the signing side as on the verifying one; Content-Digest keeps its own bound and kind.
func TestEveryCoveredValueIsBounded(t *testing.T) {
	key := testKey(t)
	exactly := "/" + strings.Repeat("p", MaxFieldBytes-1)
	if _, err := SignatureBase("GET", exactly, map[string]string{"Host": "a.example"}, []string{"@path"}, SignatureParams{}); err != nil {
		t.Errorf("a URL of exactly %d bytes: %v", MaxFieldBytes, err)
	}
	_, err := SignRequest(key, "GET", exactly+"p", map[string]string{"Host": "a.example"}, SignOptions{})
	isInvalidOptions(t, err)
	host := map[string]string{"Host": strings.Repeat("a", MaxFieldBytes+1)}
	if _, err := SignRequest(key, "GET", "/x", host, SignOptions{}); kindOf(t, err) != KindSignatureMismatch {
		t.Errorf("an oversized Host: %v", err)
	}
	note := map[string]string{"X-Note": strings.Repeat("a", MaxFieldBytes) + " "}
	if _, err := SignRequest(key, "GET", "/x", note, SignOptions{Covered: []string{"@method", "@path", "@query", "x-note"}}); kindOf(t, err) != KindSignatureMismatch {
		t.Errorf("a covered field over the bound before trimming: %v", err)
	}
	digest := map[string]string{"Content-Digest": strings.Repeat("a", MaxFieldBytes+1)}
	_, err = SignatureBase("GET", "https://a.example/x", digest, []string{"content-digest"}, SignatureParams{})
	if err != nil {
		t.Errorf("Content-Digest is not bounded as a field value: %v", err)
	}
}

package fiki

// Vectors format 3's policy (this.i @524c8qgv), where the shared vectors cannot reach: the shape of
// Go's options, and the authority rules on the signing side.

import (
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
		_, err := VerifyRequest("GET", urlQuery, headers, VerifyOptions{Authorities: served})
		if kindOf(t, err) != KindInsufficientCoverage {
			t.Errorf("expected InsufficientCoverage, got %v", err)
		}
	})
	t.Run("NoMinimum and AnyAuthority opt out of both", func(t *testing.T) {
		if _, err := VerifyRequest("GET", urlQuery, headers, VerifyOptions{NoMinimum: true, AnyAuthority: true}); err != nil {
			t.Error(err)
		}
	})
	for name, opts := range map[string]VerifyOptions{
		"no decision about authorities":     {},
		"both Authorities and AnyAuthority": {Authorities: served, AnyAuthority: true},
		"an empty Authorities":              {Authorities: []string{}},
		"both Minimum and NoMinimum":        {AnyAuthority: true, Minimum: RequestMinimum, NoMinimum: true},
	} {
		t.Run(name+" is the caller's mistake", func(t *testing.T) {
			_, err := VerifyRequest("GET", urlQuery, headers, opts)
			isInvalidOptions(t, err)
		})
	}

	request := &Request{Method: "GET", URL: urlQuery, Headers: headers}
	for name, opts := range map[string]VerifyOptions{
		"AnyAuthority":               {AnyAuthority: true},
		"both Minimum and NoMinimum": {Minimum: ResponseMinimum, NoMinimum: true},
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
	_, err = VerifyRequest("GET", "/x", headers, VerifyOptions{Authorities: []string{"kapi.example.com"}})
	if kindOf(t, err) != KindSignatureMismatch {
		t.Errorf("verifying under a Host holding U+212A: %v", err)
	}
	_, err = VerifyRequest("GET", "https://"+kelvin+"/x", headers, VerifyOptions{AnyAuthority: true})
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

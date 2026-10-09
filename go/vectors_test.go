package fiki

// The shared conformance vectors (`this.i` @5gf6r08f, @2tt6fmc0).
//
// They live at the repository root rather than under go/ so this implementation and the other four
// are held to the same bytes. A copy under each language is the drift the polyglot layout exists
// to prevent, which is why this file reaches up two directories rather than embedding anything.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func load(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "vectors", name))
	if err != nil {
		t.Fatalf("the shared vectors are not where every port reaches them: %v", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

type aidCase struct {
	ID           string `json:"id"`
	SeedHex      string `json:"seed_hex"`
	PublicKeyHex string `json:"public_key_hex"`
	AID          string `json:"aid"`
	Keyid        string `json:"keyid"`
}

type baseCase struct {
	ID        string            `json:"id"`
	SeedHex   string            `json:"seed_hex"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Covered   []string          `json:"covered"`
	Created   int64             `json:"created"`
	Keyid     string            `json:"keyid"`
	Alg       string            `json:"alg"`
	Base      string            `json:"base"`
	Signature string            `json:"signature"`
}

type requestCase struct {
	ID      string            `json:"id"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    *string           `json:"body"`
	MaxAge  *int64            `json:"max_age"`
	Now     *int64            `json:"now"`
	AID     string            `json:"aid"`
	Keyid   string            `json:"keyid"`
	Covered []string          `json:"covered"`
	Error   string            `json:"error"`
	// Format 3 (@524c8qgv): the verifier's stated policy. Minimum is "default", null for the
	// explicit opt-out, or a list; Authorities is null for the explicit opt-out or a list; Omit
	// names the fields a misuse case leaves out of the call altogether.
	Minimum     json.RawMessage `json:"minimum"`
	Authorities json.RawMessage `json:"authorities"`
	ExpectedAID *string         `json:"expected_aid"`
	Omit        []string        `json:"omit"`
	Note        string          `json:"note"`
	// Format 3 part two: a response case (responses.json, and misuse.json's kind "response").
	// ExpectedKeyid is null for the explicit decline, AnyKeyid, or an AID.
	Kind          string          `json:"kind"`
	Status        int             `json:"status"`
	Request       *vectorRequest  `json:"request"`
	ExpectedKeyid json.RawMessage `json:"expected_keyid"`
	// fields is every key the case carried, so one this driver does not know fails the case.
	fields []string
}

// verifyFields is every field a verify case may carry. A field this driver does not know fails
// the case rather than being ignored, so a field added to the vectors cannot be silently dropped by
// a port that never learned it (review V-M8).
var verifyFields = []string{"id", "method", "url", "headers", "body", "max_age", "now", "minimum",
	"authorities", "expected_aid", "note", "error", "aid", "keyid", "covered", "omit", "kind",
	"status", "request", "expected_keyid"}

// vectorRequest is the request a response case answers.
type vectorRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    *string           `json:"body"`
}

func (r *vectorRequest) asRequest() *Request {
	if r == nil {
		return nil
	}
	request := &Request{Method: r.Method, URL: r.URL, Headers: r.Headers}
	if r.Body != nil {
		request.Body = []byte(*r.Body)
	}
	return request
}

// checkFields fails a case carrying a field this driver does not know.
func checkFields(t *testing.T, id string, fields, known []string) {
	t.Helper()
	for _, name := range fields {
		if !slices.Contains(known, name) {
			t.Fatalf("unknown field %q in case %s", name, id)
		}
	}
}

// fieldsOf is every key of a JSON object.
func fieldsOf(raw []byte) ([]string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	return names, nil
}

// wellFormed is the message check every refusal passes (this.i @524c8qgv, part-two
// refinements): no control character and at most 1024 characters, so an untrusted value is
// quoted escaped and cut.
func wellFormed(t *testing.T, err error) {
	t.Helper()
	message := err.Error()
	if len(message) > 1024 {
		t.Errorf("the message is %d bytes, over 1024", len(message))
	}
	for i := 0; i < len(message); i++ {
		if message[i] < 0x20 || message[i] == 0x7f {
			t.Errorf("the message holds the control character %#x: %.200q", message[i], message)
			return
		}
	}
}

func (c *requestCase) UnmarshalJSON(raw []byte) error {
	type plain requestCase
	fields, err := fieldsOf(raw)
	if err != nil {
		return err
	}
	c.fields = fields
	return json.Unmarshal(raw, (*plain)(c))
}

func (c requestCase) body() []byte {
	if c.Body == nil {
		return nil
	}
	return []byte(*c.Body)
}

// options is the call a case describes. An error is a policy VerifyOptions cannot hold at all,
// such as authorities given as a string: Go's type system refuses it before verify is reached.
func (c requestCase) options(t *testing.T) (VerifyOptions, error) {
	t.Helper()
	opts := c.common(t)
	opts.ExpectedAID = c.ExpectedAID
	if slices.Contains(c.Omit, "authorities") {
		return opts, nil
	}
	if string(c.Authorities) == "null" {
		opts.AnyAuthority = true
		return opts, nil
	}
	return opts, json.Unmarshal(c.Authorities, &opts.Authorities)
}

// common is the policy a request and a response case share: the window, the body and the minimum.
func (c requestCase) common(t *testing.T) VerifyOptions {
	t.Helper()
	checkFields(t, c.ID, c.fields, verifyFields)
	opts := VerifyOptions{MaxAge: c.MaxAge, Body: c.body()}
	if c.Now != nil {
		opts.Now = *c.Now
	}
	switch string(c.Minimum) {
	case `"default"`:
	case "null":
		opts.NoMinimum = true
	default:
		if err := json.Unmarshal(c.Minimum, &opts.Minimum); err != nil {
			t.Fatalf("minimum %s is not \"default\", null or a list", c.Minimum)
		}
	}
	return opts
}

// verifyResponse is VerifyResponse under a response case's policy: Minimum as for a request, and
// ExpectedKeyid stated as an AID or declined with AnyKeyid, unless omit leaves it out (Go's
// spelling of the decline, this.i @524c8qgv).
func (c requestCase) verifyResponse(t *testing.T) (*Verdict, error) {
	t.Helper()
	opts := c.common(t)
	if !slices.Contains(c.Omit, "expected_keyid") {
		if string(c.ExpectedKeyid) == "null" {
			opts.AnyKeyid = true
		} else if err := json.Unmarshal(c.ExpectedKeyid, &opts.ExpectedKeyid); err != nil {
			t.Fatalf("expected_keyid %s is not null or an AID", c.ExpectedKeyid)
		}
	}
	return VerifyResponse(c.Status, c.Request.asRequest(), c.Headers, opts)
}

// policy is options for a case that must be callable, as every accept and refusal is.
func (c requestCase) policy(t *testing.T) VerifyOptions {
	t.Helper()
	opts, err := c.options(t)
	if err != nil {
		t.Fatalf("authorities %s is not a list of hosts: %v", c.Authorities, err)
	}
	return opts
}

func loadRequestCases(t *testing.T, name string) []requestCase {
	t.Helper()
	var file struct{ Cases []requestCase }
	load(t, name, &file)
	if len(file.Cases) < 5 {
		t.Fatalf("%s holds %d cases; the verify vectors are never that few", name, len(file.Cases))
	}
	return file.Cases
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestThisPortSatisfiesTheVectorsFormatItIsRunning(t *testing.T) {
	// A port running newer vectors fails here rather than passing a subset and reporting
	// conformance it no longer has: the cases it never implemented would simply not be in the
	// file it last read.
	for _, name := range []string{"aid-lens.json", "signature-base.json", "accepts.json", "refusals.json",
		"misuse.json", "signs.json", "responses.json"} {
		t.Run(name, func(t *testing.T) {
			var file struct {
				VectorsFormat int `json:"vectors_format"`
			}
			load(t, name, &file)
			if file.VectorsFormat != VectorsFormat {
				t.Errorf("%s declares vectors format %d; this port satisfies %d", name, file.VectorsFormat, VectorsFormat)
			}
		})
	}
}

func TestAIDLens(t *testing.T) {
	var file struct{ Cases []aidCase }
	load(t, "aid-lens.json", &file)
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			key, err := FromSeed(mustHex(t, c.SeedHex))
			if err != nil {
				t.Fatal(err)
			}
			if key.AID() != c.AID {
				t.Errorf("AID = %q, want %q", key.AID(), c.AID)
			}
			if key.Keyid() != c.Keyid {
				t.Errorf("keyid = %q, want %q", key.Keyid(), c.Keyid)
			}
			public, err := VerifyingKey(c.AID)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(public) != c.PublicKeyHex {
				t.Errorf("recovered key = %x, want %s", public, c.PublicKeyHex)
			}
		})
	}
}

func TestSignatureBaseVectors(t *testing.T) {
	var file struct{ Cases []baseCase }
	load(t, "signature-base.json", &file)
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			base, err := SignatureBase(c.Method, c.URL, c.Headers, c.Covered,
				SignatureParams{Created: c.Created, Keyid: c.Keyid, Alg: c.Alg})
			if err != nil {
				t.Fatal(err)
			}
			if string(base) != c.Base {
				t.Errorf("base mismatch\n got: %q\nwant: %q", base, c.Base)
			}
			// Ed25519 is deterministic, so a port that builds the right base produces the right
			// bytes — this is byte equality, not a verification round trip.
			key, err := FromSeed(mustHex(t, c.SeedHex))
			if err != nil {
				t.Fatal(err)
			}
			got := base64.StdEncoding.EncodeToString(key.Sign(base))
			if got != c.Signature {
				t.Errorf("signature = %s, want %s", got, c.Signature)
			}
		})
	}
}

func TestAcceptVectors(t *testing.T) {
	for _, c := range loadRequestCases(t, "accepts.json") {
		t.Run(c.ID, func(t *testing.T) {
			verdict, err := VerifyRequest(c.Method, c.URL, c.Headers, c.policy(t))
			if err != nil {
				t.Fatalf("expected this request to verify, got %v", err)
			}
			if verdict.AID != c.AID {
				t.Errorf("AID = %q, want %q", verdict.AID, c.AID)
			}
			// Every accept case carries the keyid as the signer wrote it (rule B18, E7).
			if c.Keyid == "" || verdict.Keyid != c.Keyid {
				t.Errorf("keyid = %q, want %q", verdict.Keyid, c.Keyid)
			}
			if !slices.Equal(verdict.Covered, c.Covered) {
				t.Errorf("covered = %v, want %v", verdict.Covered, c.Covered)
			}
		})
	}
}

func TestRefusalVectors(t *testing.T) {
	for _, c := range loadRequestCases(t, "refusals.json") {
		t.Run(c.ID, func(t *testing.T) {
			// Every entry names the kind fiki reports, so this port maps its own onto the same
			// condition rather than inventing a taxonomy of its own.
			_, err := VerifyRequest(c.Method, c.URL, c.Headers, c.policy(t))
			if err == nil {
				t.Fatalf("expected %s, got a verdict", c.Error)
			}
			var fikiErr *Error
			if !errors.As(err, &fikiErr) {
				t.Fatalf("expected a fiki.Error, got %T", err)
			}
			if fikiErr.Kind != c.Error {
				t.Errorf("kind = %s, want %s", fikiErr.Kind, c.Error)
			}
			wellFormed(t, err)
		})
	}
}

// VerifyResponse's own policy (format 3 part two): ResponseMinimum by default, and ExpectedKeyid
// a stated decision.
func TestResponseVectors(t *testing.T) {
	for _, c := range loadRequestCases(t, "responses.json") {
		t.Run(c.ID, func(t *testing.T) {
			verdict, err := c.verifyResponse(t)
			if c.Error == "" {
				if err != nil {
					t.Fatalf("expected this response to verify, got %v", err)
				}
				if verdict.Keyid != c.Keyid {
					t.Errorf("keyid = %q, want %q", verdict.Keyid, c.Keyid)
				}
				if !slices.Equal(verdict.Covered, c.Covered) {
					t.Errorf("covered = %v, want %v", verdict.Covered, c.Covered)
				}
				return
			}
			var fikiErr *Error
			if !errors.As(err, &fikiErr) {
				t.Fatalf("expected the fiki.Error %s, got %v", c.Error, err)
			}
			if fikiErr.Kind != c.Error {
				t.Errorf("kind = %s, want %s", fikiErr.Kind, c.Error)
			}
			wellFormed(t, err)
		})
	}
}

type signCase struct {
	ID              string            `json:"id"`
	Kind            string            `json:"kind"`
	SeedHex         string            `json:"seed_hex"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers"`
	Body            *string           `json:"body"`
	Covered         []string          `json:"covered"`
	Created         *int64            `json:"created"`
	Expires         *int64            `json:"expires"`
	Nonce           *string           `json:"nonce"`
	Tag             *string           `json:"tag"`
	Minimum         []string          `json:"minimum"`
	Status          *int              `json:"status"`
	Request         *vectorRequest    `json:"request"`
	Keyid           *string           `json:"keyid"`
	Label           *string           `json:"label"`
	ExpectedHeaders map[string]string `json:"expected_headers"`
	Error           string            `json:"error"`
	Note            string            `json:"note"`
	fields          []string
}

var signFields = []string{"id", "kind", "seed_hex", "method", "url", "headers", "body", "covered",
	"created", "expires", "nonce", "tag", "minimum", "status", "request", "expected_headers",
	"error", "note", "keyid", "label"}

func (c *signCase) UnmarshalJSON(raw []byte) error {
	type plain signCase
	fields, err := fieldsOf(raw)
	if err != nil {
		return err
	}
	c.fields = fields
	return json.Unmarshal(raw, (*plain)(c))
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// What the signer emits, byte for byte (review V-C4).
func TestSignVectors(t *testing.T) {
	var file struct{ Cases []signCase }
	load(t, "signs.json", &file)
	if len(file.Cases) < 5 {
		t.Fatalf("signs.json holds %d cases", len(file.Cases))
	}
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			checkFields(t, c.ID, c.fields, signFields)
			key, err := FromSeed(mustHex(t, c.SeedHex))
			if err != nil {
				t.Fatal(err)
			}
			opts := SignOptions{Covered: c.Covered, Created: deref(c.Created), Expires: deref(c.Expires),
				Nonce: deref(c.Nonce), Tag: deref(c.Tag), Minimum: c.Minimum, Keyid: deref(c.Keyid),
				Label: deref(c.Label)}
			if c.Body != nil {
				opts.Body = []byte(*c.Body)
			}
			var headers map[string]string
			switch c.Kind {
			case "request":
				headers, err = SignRequest(key, c.Method, c.URL, c.Headers, opts)
			case "response":
				headers, err = SignResponse(key, deref(c.Status), c.Request.asRequest(), c.Headers, opts)
			default:
				t.Fatalf("kind %q is neither request nor response", c.Kind)
			}
			var fikiErr *Error
			switch c.Error {
			case "":
				if err != nil {
					t.Fatalf("expected headers, got %v", err)
				}
				if !maps.Equal(headers, c.ExpectedHeaders) {
					t.Errorf("headers\n got: %q\nwant: %q", headers, c.ExpectedHeaders)
				}
			case "caller":
				if !errors.Is(err, ErrInvalidOptions) || errors.As(err, &fikiErr) {
					t.Fatalf("expected ErrInvalidOptions and no fiki.Error, got %v", err)
				}
			default:
				if !errors.As(err, &fikiErr) {
					t.Fatalf("expected the fiki.Error %s, got %v", c.Error, err)
				}
				if fikiErr.Kind != c.Error {
					t.Errorf("kind = %s, want %s", fikiErr.Kind, c.Error)
				}
				wellFormed(t, err)
			}
		})
	}
}

// A mistake in the call is ErrInvalidOptions, never an *Error (this.i @5zrf8gjk). Where the
// mistake is one VerifyOptions cannot even hold — authorities as a string, or holding a number —
// Go's type system refuses it at compile time, and the case asserts exactly that: the policy does
// not decode into the option's type, so no caller can write it.
func TestMisuseVectors(t *testing.T) {
	for _, c := range loadRequestCases(t, "misuse.json") {
		t.Run(c.ID, func(t *testing.T) {
			if c.Error != "caller" {
				t.Fatalf("error = %q, want caller", c.Error)
			}
			var err error
			if c.Kind == "response" {
				_, err = c.verifyResponse(t)
				isCallerError(t, err)
				return
			}
			opts, err := c.options(t)
			if err != nil {
				var unrepresentable *json.UnmarshalTypeError
				if !errors.As(err, &unrepresentable) {
					t.Fatalf("authorities %s: %v", c.Authorities, err)
				}
				return
			}
			_, err = VerifyRequest(c.Method, c.URL, c.Headers, opts)
			isCallerError(t, err)
		})
	}
}

func isCallerError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("expected ErrInvalidOptions, got %v", err)
	}
	var fikiErr *Error
	if errors.As(err, &fikiErr) {
		t.Fatalf("a mistake in the call came back as the fiki.Error %s", fikiErr.Kind)
	}
}

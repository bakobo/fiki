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
	// fields is every key the case carried, so one this driver does not know fails the case.
	fields []string
}

// verifyFields is every field a verify case may carry. A field this driver does not know fails
// the case rather than being ignored, so a field added to the vectors cannot be silently dropped by
// a port that never learned it (review V-M8).
var verifyFields = []string{"id", "method", "url", "headers", "body", "max_age", "now", "minimum",
	"authorities", "expected_aid", "note", "error", "aid", "keyid", "covered", "omit"}

func (c *requestCase) UnmarshalJSON(raw []byte) error {
	type plain requestCase
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, (*plain)(c)); err != nil {
		return err
	}
	for name := range fields {
		c.fields = append(c.fields, name)
	}
	return nil
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
	for _, name := range c.fields {
		if !slices.Contains(verifyFields, name) {
			t.Fatalf("unknown field %q in case %s", name, c.ID)
		}
	}
	opts := VerifyOptions{MaxAge: c.MaxAge, Body: c.body()}
	if c.Now != nil {
		opts.Now = *c.Now
	}
	if c.ExpectedAID != nil {
		opts.ExpectedAID = *c.ExpectedAID
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
	if slices.Contains(c.Omit, "authorities") {
		return opts, nil
	}
	if string(c.Authorities) == "null" {
		opts.AnyAuthority = true
		return opts, nil
	}
	return opts, json.Unmarshal(c.Authorities, &opts.Authorities)
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
	if len(file.Cases) <= 5 {
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
		"misuse.json"} {
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
			opts, err := c.options(t)
			if err != nil {
				var unrepresentable *json.UnmarshalTypeError
				if !errors.As(err, &unrepresentable) {
					t.Fatalf("authorities %s: %v", c.Authorities, err)
				}
				return
			}
			_, err = VerifyRequest(c.Method, c.URL, c.Headers, opts)
			if !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("expected ErrInvalidOptions, got %v", err)
			}
			var fikiErr *Error
			if errors.As(err, &fikiErr) {
				t.Fatalf("a mistake in the call came back as the fiki.Error %s", fikiErr.Kind)
			}
		})
	}
}

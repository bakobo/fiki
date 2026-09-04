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
	Covered []string          `json:"covered"`
	Error   string            `json:"error"`
}

func (c requestCase) body() []byte {
	if c.Body == nil {
		return nil
	}
	return []byte(*c.Body)
}

func (c requestCase) options() VerifyOptions {
	opts := VerifyOptions{MaxAge: c.MaxAge, Body: c.body()}
	if c.Now != nil {
		opts.Now = *c.Now
	}
	return opts
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
	for _, name := range []string{"aid-lens.json", "signature-base.json", "accepts.json", "refusals.json"} {
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
	var file struct{ Cases []requestCase }
	load(t, "accepts.json", &file)
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			verdict, err := VerifyRequest(c.Method, c.URL, c.Headers, c.options())
			if err != nil {
				t.Fatalf("expected this request to verify, got %v", err)
			}
			if verdict.AID != c.AID {
				t.Errorf("AID = %q, want %q", verdict.AID, c.AID)
			}
			if !slices.Equal(verdict.Covered, c.Covered) {
				t.Errorf("covered = %v, want %v", verdict.Covered, c.Covered)
			}
		})
	}
}

func TestRefusalVectors(t *testing.T) {
	var file struct{ Cases []requestCase }
	load(t, "refusals.json", &file)
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			// Every entry names the kind fiki reports, so this port maps its own onto the same
			// condition rather than inventing a taxonomy of its own.
			_, err := VerifyRequest(c.Method, c.URL, c.Headers, c.options())
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

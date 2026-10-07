// Release smoke test for github.com/bakobo/fiki/go, built against the version the module proxy
// serves, never the source. The same four checks as every port's smoke test (docs/releasing.md):
// a plain vector, a plain round trip, a KERI vector through a resolver, and a KERI round trip
// under a caller-chosen AID keyid. Usage: go run . <vectors-dir>
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	fiki "github.com/bakobo/fiki/go"
)

type keyEntry struct {
	Keyid        string `json:"keyid"`
	EffectiveKey string `json:"effective_key"`
	SeedHex      string `json:"seed_hex"`
}

func load(v any, parts ...string) {
	raw, err := os.ReadFile(filepath.Join(parts...))
	must(err)
	must(json.Unmarshal(raw, v))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

// passed counts the checks that ran, so a case renamed out of a vector file fails the smoke test
// instead of skipping it.
var passed int

func check(name, got, want string) {
	if got != want {
		fmt.Fprintf(os.Stderr, "FAIL %s: got %q, want %q\n", name, got, want)
		os.Exit(1)
	}
	fmt.Println("ok  ", name)
	passed++
}

func main() {
	vectors := os.Args[1]

	var accepts struct {
		Cases []struct {
			ID, Method, URL, AID string
			Headers              map[string]string
			Now                  int64
		} `json:"cases"`
	}
	load(&accepts, vectors, "accepts.json")
	for _, c := range accepts.Cases {
		if c.ID != "default-covered-get" {
			continue
		}
		verdict, err := fiki.VerifyRequest(c.Method, c.URL, c.Headers, fiki.VerifyOptions{Now: c.Now})
		must(err)
		check("plain vector", verdict.AID, c.AID)
	}

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	key, err := fiki.FromSeed(seed)
	must(err)
	url, body, maxAge := "https://api.example.com/things?limit=1", []byte(`{"hello": "world"}`), int64(300)
	headers, err := fiki.SignRequest(key, "POST", url, nil, fiki.SignOptions{Body: body})
	must(err)
	verdict, err := fiki.VerifyRequest("POST", url, headers,
		fiki.VerifyOptions{Body: body, MaxAge: &maxAge, ExpectedAID: key.AID()})
	must(err)
	check("plain round trip", verdict.AID, key.AID())

	var keri struct {
		Policy struct {
			MaxAge int64 `json:"max_age"`
			Skew   int64 `json:"skew"`
		} `json:"policy"`
		Keys  []keyEntry `json:"keys"`
		Cases []struct {
			ID      string `json:"id"`
			Request struct {
				Method, URL string
				Headers     map[string]string
			} `json:"request"`
			Now      int64 `json:"now"`
			Expected struct {
				Keyid string `json:"keyid"`
			} `json:"expected"`
		} `json:"cases"`
	}
	load(&keri, vectors, "keri", "requests.json")
	table := map[string]keyEntry{}
	for _, k := range keri.Keys {
		table[k.Keyid] = k
	}
	resolve := func(keyid string) ([]byte, error) {
		entry, ok := table[keyid]
		if !ok || entry.EffectiveKey == "" {
			return nil, nil
		}
		return base64.RawURLEncoding.DecodeString(entry.EffectiveKey)
	}
	for _, c := range keri.Cases {
		if c.ID != "get-with-query" {
			continue
		}
		verdict, err := fiki.VerifyRequest(c.Request.Method, c.Request.URL, c.Request.Headers, fiki.VerifyOptions{
			MaxAge: &keri.Policy.MaxAge, Skew: &keri.Policy.Skew, Now: c.Now, Resolve: resolve,
			Minimum: fiki.RequestMinimum,
		})
		must(err)
		check("KERI vector", verdict.AID, c.Expected.Keyid)

		controller := table[c.Expected.Keyid]
		controllerSeed, err := hex.DecodeString(controller.SeedHex)
		must(err)
		signer, err := fiki.FromSeed(controllerSeed)
		must(err)
		url := "https://keria.example.com/identifiers?type=rot"
		headers, err := fiki.SignRequest(signer, "GET", url, nil,
			fiki.SignOptions{Keyid: controller.Keyid, Minimum: fiki.RequestMinimum})
		must(err)
		verdict, err = fiki.VerifyRequest("GET", url, headers,
			fiki.VerifyOptions{MaxAge: &maxAge, Resolve: resolve, Minimum: fiki.RequestMinimum})
		must(err)
		check("KERI round trip", verdict.AID, controller.Keyid)
	}
	if passed != 4 {
		fmt.Fprintf(os.Stderr, "FAIL: %d of 4 checks ran; a named vector case is missing\n", passed)
		os.Exit(1)
	}
}

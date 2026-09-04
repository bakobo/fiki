package fiki_test

// The samples in docs/user-guide.md, run.
//
// A guide whose code does not compile is worse than no guide: a reader trusts it, pastes it, and
// loses an hour to an API that moved. This is an external test package on purpose, so it sees only
// what a consumer sees.

import (
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
		fiki.VerifyOptions{Body: body, MaxAge: &maxAge})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.AID != key.AID() {
		t.Errorf("AID = %q, want %q", verdict.AID, key.AID())
	}
}

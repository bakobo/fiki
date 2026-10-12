package fiki

// fiki-go runs the key-spelling vectors, vectors/keys/keys.json (`this.i` @0mvgkwnl).
//
// AIDFrom turns any of the public-key spellings into the canonical AID, and FromOpenSSH loads an
// unencrypted OpenSSH private key. Neither touches the wire: a fiki-signed request still carries
// the raw key in its keyid (@7xrx5evg), and a verifier still compares AIDs.

import (
	"bytes"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// Every section's case count, read once from keys.json at hardening-a and never at test time, so
// a section emptied or cut short fails here rather than passing on what it still holds.
var keyCounts = map[string]int{
	"keys/public/accepts":   18,
	"keys/public/refusals":  72,
	"keys/private/accepts":  7,
	"keys/private/refusals": 43,
}

type keyCase struct {
	ID        string `json:"id"`
	Input     string `json:"input"`
	AID       string `json:"aid"`
	Signature string `json:"signature"`
	Error     string `json:"error"`
}

type keyFile struct {
	KeyVectorsFormat *int   `json:"key_vectors_format"`
	MaxPublicChars   int    `json:"max_public_chars"`
	MaxPrivateChars  int    `json:"max_private_chars"`
	SignedMessage    string `json:"signed_message"`
	Public           struct {
		Accepts  []keyCase `json:"accepts"`
		Refusals []keyCase `json:"refusals"`
	} `json:"public"`
	Private struct {
		Accepts  []keyCase `json:"accepts"`
		Refusals []keyCase `json:"refusals"`
	} `json:"private"`
}

func loadKeys(t *testing.T) keyFile {
	t.Helper()
	var file keyFile
	load(t, "keys/keys.json", &file)
	return file
}

func findKeyCase(t *testing.T, cases []keyCase, id string) keyCase {
	t.Helper()
	for _, c := range cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no case %q", id)
	return keyCase{}
}

func TestThisPortSatisfiesTheKeyVectorsFormatItIsRunning(t *testing.T) {
	file := loadKeys(t)
	if file.KeyVectorsFormat == nil || *file.KeyVectorsFormat != KeyVectorsFormat {
		t.Errorf("keys.json declares key_vectors_format %v; this port satisfies %d", file.KeyVectorsFormat, KeyVectorsFormat)
	}
	if file.MaxPublicChars != maxPublicChars || file.MaxPrivateChars != maxPrivateChars {
		t.Errorf("keys.json bounds %d and %d; this port has %d and %d",
			file.MaxPublicChars, file.MaxPrivateChars, maxPublicChars, maxPrivateChars)
	}
}

// asMalformedKey is the refusal as fiki's *Error of kind MalformedKey, wrapping nothing that
// might carry the input, or a failed test.
func asMalformedKey(t *testing.T, err error) *Error {
	t.Helper()
	if err == nil {
		t.Fatal("accepted")
	}
	fe, ok := err.(*Error)
	if !ok || fe.Kind != KindMalformedKey {
		t.Fatalf("refused as %T %v, want MalformedKey", err, err)
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("the refusal wraps %v", errors.Unwrap(err))
	}
	return fe
}

var publicRun = regexp.MustCompile(`[A-Za-z0-9+/=_-]{12,}`)
var privateRun = regexp.MustCompile(`[A-Za-z0-9+/=]{16,}`)

// echoes reports whether the error carries text, or any run of it long enough to hold key material.
func echoes(e *Error, text string) bool {
	if e.Keyid != "" || (len(text) >= 12 && strings.Contains(e.Message, text)) {
		return true
	}
	for _, run := range publicRun.FindAllString(text, -1) {
		if strings.Contains(e.Message, run) {
			return true
		}
	}
	return false
}

func TestAPublicSpellingConvertsToItsAID(t *testing.T) {
	cases := loadKeys(t).Public.Accepts
	ran := pinned(t, keyCounts, "keys/public/accepts", len(cases))
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			ran()
			aid, err := AIDFrom(c.Input)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if aid != c.AID {
				t.Errorf("AID %q, want %q", aid, c.AID)
			}
		})
	}
}

func TestAMalformedPublicSpellingIsRefusedWithoutEchoingIt(t *testing.T) {
	// Never echoed, because what a caller hands AIDFrom by mistake can be a private key: the .key
	// file instead of the .pub, or a seed in base64url, which is 43 characters like a raw key.
	cases := loadKeys(t).Public.Refusals
	ran := pinned(t, keyCounts, "keys/public/refusals", len(cases))
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			ran()
			if c.Error != KindMalformedKey {
				t.Fatalf("case expects %s", c.Error)
			}
			aid, err := AIDFrom(c.Input)
			e := asMalformedKey(t, err)
			if aid != "" {
				t.Errorf("returned %q beside the refusal", aid)
			}
			if echoes(e, c.Input) {
				t.Errorf("the refusal echoes its input: %s", e.Message)
			}
		})
	}
}

func TestAnOpenSSHKeyLoadsAndSignsAsItsSeed(t *testing.T) {
	file := loadKeys(t)
	cases := file.Private.Accepts
	ran := pinned(t, keyCounts, "keys/private/accepts", len(cases))
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			ran()
			key, err := FromOpenSSH(c.Input)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if key.AID() != c.AID {
				t.Errorf("AID %q, want %q", key.AID(), c.AID)
			}
			signature := b64url.EncodeToString(key.Sign([]byte(file.SignedMessage)))
			if signature != c.Signature {
				t.Errorf("signature %q, want %q", signature, c.Signature)
			}
		})
	}
}

func TestAMalformedOpenSSHKeyIsRefusedWithoutEchoingIt(t *testing.T) {
	cases := loadKeys(t).Private.Refusals
	ran := pinned(t, keyCounts, "keys/private/refusals", len(cases))
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			ran()
			if c.Error != KindMalformedKey {
				t.Fatalf("case expects %s", c.Error)
			}
			key, err := FromOpenSSH(c.Input)
			e := asMalformedKey(t, err)
			if key != nil {
				t.Error("returned a key beside the refusal")
			}
			// A private key never reaches an error: not its text, not any run of its base64 body
			// long enough to carry key material, and not the keyid field a consumer might log.
			if e.Keyid != "" {
				t.Errorf("keyid %q", e.Keyid)
			}
			for _, run := range privateRun.FindAllString(c.Input, -1) {
				if strings.Contains(e.Message, run) {
					t.Errorf("the refusal echoes %q", run)
				}
			}
		})
	}
}

func TestAWeakKeyIsRefusedForItsWeaknessWhateverItsSpelling(t *testing.T) {
	// Not merely refused: refused by the point check, so the spelling parsed and the key reached
	// it (@37wdchu5). A parser bug that refused these earlier would pass the vector alone.
	weak := regexp.MustCompile(`small order|canonical encoding of a point`)
	n := 0
	for _, c := range loadKeys(t).Public.Refusals {
		if !strings.HasSuffix(c.ID, "small-order") && !strings.HasSuffix(c.ID, "not-on-curve") {
			continue
		}
		n++
		_, err := AIDFrom(c.Input)
		if e := asMalformedKey(t, err); !weak.MatchString(e.Message) {
			t.Errorf("%s: refused as %q", c.ID, e.Message)
		}
	}
	if n == 0 {
		t.Fatal("no weak-key cases")
	}
}

func TestAPrivateKeyWithAWeakPublicKeyIsRefused(t *testing.T) {
	c := findKeyCase(t, loadKeys(t).Private.Refusals, "public-small-order")
	_, err := FromOpenSSH(c.Input)
	if e := asMalformedKey(t, err); !regexp.MustCompile(`does not derive|small order`).MatchString(e.Message) {
		t.Errorf("refused as %q", e.Message)
	}
}

func TestACanonicalTransferableOrDigestAIDIsToldToResolveIt(t *testing.T) {
	refusals := loadKeys(t).Public.Refusals
	for _, id := range []string{"aid-transferable", "aid-digest"} {
		_, err := AIDFrom(findKeyCase(t, refusals, id).Input)
		if e := asMalformedKey(t, err); !strings.Contains(e.Message, "resolve it") {
			t.Errorf("%s: refused as %q", id, e.Message)
		}
	}
}

func TestAMalformedDPrefixIsNotCalledAnAID(t *testing.T) {
	// Shape before meaning: text that merely starts with D is not told it is a transferable AID.
	refusals := loadKeys(t).Public.Refusals
	for _, id := range []string{"aid-transferable-not-base64", "aid-transferable-misspelled"} {
		_, err := AIDFrom(findKeyCase(t, refusals, id).Input)
		if e := asMalformedKey(t, err); strings.Contains(e.Message, "resolve it") {
			t.Errorf("%s: refused as %q", id, e.Message)
		}
	}
}

func TestASeedMistakenForARawKeyIsNotEchoedWhenRefused(t *testing.T) {
	// About half of all seeds, written as 43 characters of base64url, are not a valid point and so
	// are refused by the curve check rather than by the parser. That refusal must not quote it.
	var seed []byte
	for n := 0; n < 256 && seed == nil; n++ {
		if candidate := bytes.Repeat([]byte{byte(n)}, 32); !canonicalPoint(candidate) {
			seed = candidate
		}
	}
	text := base64.RawURLEncoding.EncodeToString(seed)
	_, err := AIDFrom(text)
	e := asMalformedKey(t, err)
	if !strings.Contains(e.Message, "not the canonical encoding of a point") {
		t.Errorf("refused as %q", e.Message)
	}
	if echoes(e, text) {
		t.Errorf("the refusal echoes the seed: %s", e.Message)
	}
}

func TestTheEncryptedRefusalSaysToKeepADedicatedKey(t *testing.T) {
	c := findKeyCase(t, loadKeys(t).Private.Refusals, "encrypted")
	_, err := FromOpenSSH(c.Input)
	if e := asMalformedKey(t, err); !strings.Contains(e.Message, "dedicated") {
		t.Errorf("refused as %q", e.Message)
	}
}

// Go strings are bytes and may hold invalid UTF-8, which JSON cannot carry portably; each is a
// refusal like any other, never a panic, in either function and anywhere in the input.
func TestInvalidUTF8IsMalformedKeyNotACrash(t *testing.T) {
	file := loadKeys(t)
	public := findKeyCase(t, file.Public.Accepts, "ssh-comment").Input
	private := findKeyCase(t, file.Private.Accepts, "ssh-keygen").Input
	for _, at := range []int{0, 1, 20, len(public) / 2, len(public) - 1, len(public)} {
		_, err := AIDFrom(public[:at] + "\xff" + public[at:])
		asMalformedKey(t, err)
	}
	for _, text := range []string{"\xff", "\xed\xa0\x80", strings.Repeat("\xff", 43), strings.Repeat("\xff", 44)} {
		_, err := AIDFrom(text)
		asMalformedKey(t, err)
	}
	for _, at := range []int{0, 1, 40, len(private) / 2, len(private) - 2, len(private)} {
		_, err := FromOpenSSH(private[:at] + "\xff" + private[at:])
		asMalformedKey(t, err)
	}
}

// A bound counts characters, as every port does, so a refusal's length is the one a caller sees.
func TestTheBoundsCountCharactersNotBytes(t *testing.T) {
	_, err := AIDFrom(strings.Repeat("é", maxPublicChars+1))
	if e := asMalformedKey(t, err); !strings.Contains(e.Message, "this one is 1025") {
		t.Errorf("refused as %q", e.Message)
	}
	_, err = FromOpenSSH(strings.Repeat("é", maxPrivateChars+1))
	if e := asMalformedKey(t, err); !strings.Contains(e.Message, "over 4096 characters") {
		t.Errorf("refused as %q", e.Message)
	}
}

func TestAnSSHKeySignsARequestThatVerifiesAgainstItsRegisteredPublicLine(t *testing.T) {
	file := loadKeys(t)
	key, err := FromOpenSSH(findKeyCase(t, file.Private.Accepts, "ssh-keygen").Input)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := AIDFrom(findKeyCase(t, file.Public.Accepts, "ssh-keygen-pub").Input)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := SignRequest(key, "GET", "https://example.com/x", nil, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	maxAge := int64(60)
	verdict, err := VerifyRequest("GET", "https://example.com/x", headers,
		VerifyOptions{MaxAge: &maxAge, AnyAuthority: true, ExpectedAID: String(registered)})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.AID != registered {
		t.Errorf("verdict AID %q, want %q", verdict.AID, registered)
	}
}

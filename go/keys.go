package fiki

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"regexp"
	"strings"
)

// CESR's Ed25519N (non-transferable Ed25519 verification key). fiki decodes this code and no
// other: a decoder that handles one fixed-length code can only ever be narrower than a full CESR
// implementation, which is the safe direction for a differential.
const (
	code    = "B"
	rawLen  = ed25519.PublicKeySize
	qb64Len = 44
)

var b64url = base64.URLEncoding.WithPadding(base64.NoPadding)

// 44 characters of base64url and nothing else. "=" is inside base64's alphabet, so a lenient
// decoder would accept a padded AID that decodes short — and a decoder is exactly the place a
// quiet shortfall turns into somebody else's error.
var aidShape = regexp.MustCompile(`^[A-Za-z0-9\-_]{44}$`)

// ToAID renders a raw 32-byte Ed25519 public key as a non-transferable AID.
func ToAID(raw []byte) string {
	padded := make([]byte, rawLen+1)
	copy(padded[1:], raw)
	return code + base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(padded)[1:]
}

// VerifyingKey recovers the raw Ed25519 public key from a non-transferable AID.
func VerifyingKey(aid string) (ed25519.PublicKey, error) {
	if len(aid) != qb64Len || !strings.HasPrefix(aid, code) {
		return nil, &Error{
			Kind: KindMalformedKey,
			Message: "A non-transferable AID is 44 characters beginning with \"" + code +
				"\"; this one is not.",
			Keyid: aid,
		}
	}
	if !aidShape.MatchString(aid) {
		return nil, &Error{Kind: KindMalformedKey, Message: "The AID " + aid + " is not valid base64url.", Keyid: aid}
	}
	// No error check on the decode: the pattern above already established 44 characters of the
	// base64url alphabet with no padding, so this cannot fail. A branch that cannot be taken is a
	// guard claiming to guard something.
	decoded, _ := b64url.DecodeString("A" + aid[1:])
	return ed25519.PublicKey(decoded[1:]), nil
}

// Key is an Ed25519 key pair whose public half is rendered as a non-transferable AID.
type Key struct {
	private ed25519.PrivateKey
}

// Generate creates a key from fresh randomness.
//
// No error return: ed25519.GenerateKey draws from crypto/rand, which does not fail on any
// platform Go supports — it panics if the operating system's randomness is unavailable, and a
// caller has nothing useful to do about that either way.
func Generate() *Key {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	return &Key{private: private}
}

// FromSeed recreates a key from its 32-byte Ed25519 seed.
func FromSeed(seed []byte) (*Key, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errorf(KindMalformedKey, "An Ed25519 seed is %d bytes; this one is %d.", ed25519.SeedSize, len(seed))
	}
	return &Key{private: ed25519.NewKeyFromSeed(seed)}, nil
}

// AID is the non-transferable AID: 44 characters, "B" prefixed, and also the verifying key.
func (k *Key) AID() string { return ToAID(k.private.Public().(ed25519.PublicKey)) }

// Keyid is the raw verifying key, base64url and unpadded — the RFC 8037 JWK "x" form
// (this.i @7xrx5evg).
func (k *Key) Keyid() string { return b64url.EncodeToString(k.private.Public().(ed25519.PublicKey)) }

// Seed is the 32-byte seed, for a caller that has to persist the key somewhere.
func (k *Key) Seed() []byte { return k.private.Seed() }

// Sign returns the raw 64-byte Ed25519 signature over data.
func (k *Key) Sign(data []byte) []byte { return ed25519.Sign(k.private, data) }

func b64std(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

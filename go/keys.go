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

// VerifyingKey recovers the raw Ed25519 public key from a non-transferable AID. Anything else is
// MalformedKey: a string that is not the canonical spelling of a B AID, and a key that is not a
// canonical on-curve point or is of small order.
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
		return nil, &Error{Kind: KindMalformedKey, Message: "The AID " + brief(aid) + " is not valid base64url.", Keyid: aid}
	}
	// No error check on the decode: the pattern above already established 44 characters of the
	// base64url alphabet with no padding, so this cannot fail. A branch that cannot be taken is a
	// guard claiming to guard something.
	decoded, _ := b64url.DecodeString("A" + aid[1:])
	// The second character's top two bits land in the pad byte the code replaced, so a non-zero
	// pad would give one key two spellings. Only the canonical one, the one ToAID produces, is the
	// AID (bakobo/fiki#4).
	if decoded[0] != 0 {
		return nil, &Error{Kind: KindMalformedKey, Message: "The AID " + brief(aid) + " is not the canonical spelling of its key.", Keyid: aid}
	}
	// A key no honest signer holds is refused here too, so the decoder alone answers whether an
	// AID names a usable key (@8krqtpsu, @7w7nv94j).
	public, _, err := usable(ed25519.PublicKey(decoded[1:]), aid, aid)
	return public, err
}

// keripy's PreDex, the prefix derivation codes an AID may carry, with the raw size each encodes
// (this.i @37rktct3). fiki reads none of them but B; it needs the table only to say whether a keyid
// is a well-formed AID, which the KERI profile's R1 makes the verifier's job before any key store
// is asked.
var prefixCodes = map[string]int{
	"B": 32, "D": 32, "E": 32, "F": 32, "G": 32, "H": 32, "I": 32,
	"0D": 64, "0E": 64, "0F": 64, "0G": 64,
	"1AAA": 33, "1AAB": 33, "1AAI": 33, "1AAJ": 33,
	"1AAC": 57, "1AAD": 57,
	"1AAE": 114,
}

// otherNonTransferable are the non-transferable codes other than B: secp256k1, Ed448 and
// secp256r1 keys, whose algorithm the profile does not support.
var otherNonTransferable = map[string]bool{"1AAA": true, "1AAC": true, "1AAI": true}

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

// rawKeyidShape is the RFC 8037 "x" form of a raw keyid: 32 bytes, base64url, unpadded, which is
// 43 characters. Checked before decoding because Go's decoder skips CR and LF wherever they are.
var rawKeyidShape = regexp.MustCompile(`^[A-Za-z0-9\-_]{43}$`)

// Keyid is the raw verifying key, base64url and unpadded — the RFC 8037 JWK "x" form
// (this.i @7xrx5evg).
func (k *Key) Keyid() string { return b64url.EncodeToString(k.private.Public().(ed25519.PublicKey)) }

// Seed is the 32-byte seed, for a caller that has to persist the key somewhere.
func (k *Key) Seed() []byte { return k.private.Seed() }

// Sign returns the raw 64-byte Ed25519 signature over data.
func (k *Key) Sign(data []byte) []byte { return ed25519.Sign(k.private, data) }

func b64std(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

// aidCode is the PreDex code of keyid when it is a well-formed AID under the KERI vectors'
// keys_rule (this.i @7w7nv94j, @37rktct3), and false otherwise. The code is one, two or four
// characters by its first character, as CESR sizes it; the raw bytes behind it are padded with zero
// bytes to a multiple of three, base64url-encoded, and the code written over the characters the
// padding became. Well formed means exactly that spelling: the right length, base64url throughout,
// and zero pad bits, so that re-encoding gives back the keyid. fiki checks this before any resolver
// sees a keyid, so a resolver only ever answers about key state.
func aidCode(keyid string) (string, bool) {
	if keyid == "" {
		return "", false
	}
	size := 4
	switch first := keyid[0]; {
	case first >= 'A' && first <= 'Z' || first >= 'a' && first <= 'z':
		size = 1
	case first == '0':
		size = 2
	}
	if len(keyid) < size {
		return "", false
	}
	code := keyid[:size]
	length, known := prefixCodes[code]
	if !known {
		return "", false
	}
	pad := (3 - length%3) % 3
	if len(keyid) != (pad+length)*4/3+size-pad {
		return "", false
	}
	// Strict, so non-zero trailing bits are refused; the shape is checked again by re-encoding.
	decoded, err := b64url.Strict().DecodeString(strings.Repeat("A", pad) + keyid[size:])
	if err != nil {
		return "", false
	}
	spelled := b64url.EncodeToString(append(make([]byte, pad), decoded[pad:]...))[pad:]
	return code, code+spelled == keyid
}

// wellFormedAID is true when keyid is a well-formed AID under the KERI vectors' keys_rule.
func wellFormedAID(keyid string) bool {
	_, ok := aidCode(keyid)
	return ok
}

// aidKey is the key a well-formed B keyid carries, read as an AID's key: canonical, on the curve,
// not of small order, and in the prime-order subgroup (this.i @37rktct3).
func aidKey(keyid string) (ed25519.PublicKey, error) {
	decoded, _ := b64url.DecodeString("A" + keyid[1:]) // well formed already, so this cannot fail
	public := ed25519.PublicKey(decoded[1:])
	if err := subgroupDefect(public, "The key for "+shown(keyid), keyid); err != nil {
		return nil, err
	}
	return public, nil
}

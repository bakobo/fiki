package fiki

// Other spellings of an Ed25519 public key, read at the edge of the API (`this.i` @0mvgkwnl).
//
// AIDFrom turns a public key spelled as an AID, as raw base64url (the wire keyid of @7xrx5evg,
// also a JWK's "x"), as a base58btc did:key, as a did:peer with numalgo 0, or as an OpenSSH public
// line into the canonical AID. The OpenSSH private-key reader is openssh.go.
//
// Nothing here touches a request. A verifier calls AIDFrom when it loads its registrations, so a
// bad one fails at configuration time rather than on a live request, and ExpectedAID stays a
// single spelling. Every spelling has exactly one accepted form: each decoder below re-encodes
// what it decoded, or reads a shape that admits no second spelling, so no key has two spellings
// that both pass. Every decoded key then goes through keyDefect, so no spelling is a way around
// the small-order refusal (@37wdchu5).

import (
	"bytes"
	"math/big"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Checked before anything is decoded, so nothing below ever sees more than this (input-handling
// standard: size, then shape, then meaning). An OpenSSH public line's comment is the only part of
// any spelling that varies much, and 1024 characters leaves it ample room.
const maxPublicChars = 1024

const (
	rawB64urlLen = 43
	// A base58btc value over 34 bytes is at most 47 characters after the "z"; anything longer
	// cannot be an Ed25519 did:key, and refusing it first keeps the big-integer arithmetic small.
	maxMultibase = 48
)

// multicodec ed25519-pub, 0xed as an unsigned varint.
var ed25519Pub = []byte{0xed, 0x01}

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var b64urlText = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

// "ssh-ed25519", one space, the blob, and optionally one space and a printable-ASCII comment that
// neither begins nor ends with a space, so that no whitespace around any field is ever ignored.
// RE2's $ is the end of the text, never before a final newline.
var sshLine = regexp.MustCompile(`^ssh-ed25519 ([A-Za-z0-9+/=]+)(?: ([\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?))?$`)

// canonicalB64url is unpadded base64url, or nil unless text is the one canonical spelling of its
// bytes.
func canonicalB64url(text string) []byte {
	if !b64urlText.MatchString(text) || len(text)%4 == 1 {
		return nil
	}
	// The shape check makes the decode infallible: the alphabet, no padding, and a length that
	// leaves no lone character. Go's decoder accepts non-zero spare bits, so the re-encoding is
	// what refuses a second spelling.
	data, _ := b64url.DecodeString(text)
	if b64url.EncodeToString(data) != text {
		return nil
	}
	return data
}

// base58btc is the bytes text spells, or nil. Leading "1"s are zero bytes, so every string has
// exactly one meaning, and the decoding is the inverse of the encoding with no second spelling.
func base58btc(text string) []byte {
	number := new(big.Int)
	radix := big.NewInt(58)
	for i := 0; i < len(text); i++ {
		digit := strings.IndexByte(b58Alphabet, text[i])
		if digit < 0 {
			return nil
		}
		number.Mul(number, radix).Add(number, big.NewInt(int64(digit)))
	}
	zeros := len(text) - len(strings.TrimLeft(text, "1"))
	return append(make([]byte, zeros), number.Bytes()...)
}

// multibaseEd25519 is the raw key under a did:key multibase value, which is base58btc ("z") only.
//
// The did:key ABNF also admits base64url ("u"), but the spec's resolution algorithm requires the
// value to "begin with the letter `z`" or raise invalidDid, and the peer DID ABNF has transform =
// "z". Reading "u" too would give every key two DIDs.
func multibaseEd25519(value string) []byte {
	if len(value) > maxMultibase || !strings.HasPrefix(value, "z") {
		return nil
	}
	decoded := base58btc(value[1:])
	if len(decoded) != len(ed25519Pub)+rawLen || !bytes.Equal(decoded[:2], ed25519Pub) {
		return nil
	}
	return decoded[2:]
}

// aidBody is the 32 bytes under a canonically spelled 44-character B, D or E AID, or nil.
func aidBody(text string) []byte {
	if !wellFormedAID(text) {
		return nil
	}
	decoded, _ := b64url.DecodeString("A" + text[1:]) // infallible once wellFormedAID holds
	return decoded[1:]
}

// rawOf is the raw key text spells, by its shape, or nil for a shape fiki does not read.
func rawOf(text string) []byte {
	switch {
	case len(text) == qb64Len && text[0] == 'B':
		return aidBody(text)
	case len(text) == rawB64urlLen:
		return canonicalB64url(text)
	case strings.HasPrefix(text, "did:key:"):
		return multibaseEd25519(text[len("did:key:"):])
	case strings.HasPrefix(text, "did:peer:0"):
		return multibaseEd25519(text[len("did:peer:0"):])
	}
	if line := sshLine.FindStringSubmatch(text); line != nil {
		if blob := canonicalB64std(line[1]); blob != nil {
			return sshPublicBlob(blob)
		}
	}
	return nil
}

// AIDFrom is the canonical AID of the Ed25519 public key text spells.
//
// text is an AID, the raw key as 43 characters of unpadded base64url (a JWK's "x"), a did:key, a
// did:peer with numalgo 0, or an OpenSSH public line: "ssh-ed25519", one space, the blob, and
// optionally one space and a printable-ASCII comment that neither begins nor ends with a space.
// Length, not the first character, tells raw from AID: 43 against 44. Nothing around text is
// stripped; that is the caller's, so that one input never has two readings.
//
// Anything else is an *Error of kind MalformedKey, including a transferable or digest AID, whose
// key is not the identifier's to give. The error never quotes text and its Keyid is empty, because
// what is handed here by mistake can be a private key: the .key file instead of the .pub, or a
// seed, which in base64url is 43 characters like a raw key.
//
// Call it when you load your registrations rather than on each request.
func AIDFrom(text string) (string, error) {
	if n := utf8.RuneCountInString(text); n > maxPublicChars {
		return "", errorf(KindMalformedKey, "A public key is at most %d characters in any spelling "+
			"fiki reads; this one is %d.", maxPublicChars, n)
	}
	// Shape before meaning: only a canonically spelled D or E AID is told what it is.
	if text != "" && (text[0] == 'D' || text[0] == 'E') && wellFormedAID(text) {
		return "", errorf(KindMalformedKey, "The text is a transferable or digest AID, whose "+
			"current key is not recoverable from the identifier; resolve it to a key first.")
	}
	raw := rawOf(text)
	if raw == nil {
		return "", errorf(KindMalformedKey, "The text, %d characters, is not an Ed25519 public key "+
			"in any spelling fiki reads: an AID, raw base64url, a base58btc did:key, a did:peer:0, "+
			"or an ssh-ed25519 line.", utf8.RuneCountInString(text))
	}
	if err := keyDefect(raw, "The key given", ""); err != nil {
		return "", err
	}
	return ToAID(raw), nil
}

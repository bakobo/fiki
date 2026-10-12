package fiki

// Unencrypted OpenSSH Ed25519 private keys, for FromOpenSSH (`this.i` @0mvgkwnl).
//
// The seed this returns derives its own public key, and a seed always derives a point of prime
// order, so the small-order refusal of @37wdchu5 cannot fire here once the stored public key is
// checked against the derived one.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Checked before anything is decoded (input-handling standard: size, then shape, then meaning).
const maxPrivateChars = 4096

const (
	opensshBegin = "-----BEGIN OPENSSH PRIVATE KEY-----"
	opensshEnd   = "-----END OPENSSH PRIVATE KEY-----"
	opensshMagic = "openssh-key-v1\x00"
	sshEd25519   = "ssh-ed25519"
)

var b64stdText = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

// canonicalB64std is padded standard base64, or nil unless text is the one canonical spelling.
// Also used by formats.go, which reads the same encoding in a public key line.
func canonicalB64std(text string) []byte {
	if !b64stdText.MatchString(text) || len(text)%4 != 0 {
		return nil
	}
	// The shape check makes the decode infallible: every quantum of a length divisible by four,
	// with at most two "=" and only at the end, is XXXX, XXX= or XX==. Go's decoder accepts
	// non-zero spare bits, so the re-encoding is what refuses a second spelling.
	data, _ := base64.StdEncoding.DecodeString(text)
	if base64.StdEncoding.EncodeToString(data) != text {
		return nil
	}
	return data
}

// sshReader reads RFC 4251 section 5 wire fields, refusing any length that overruns what is there.
type sshReader struct {
	data []byte
	pos  int
}

func (r *sshReader) uint32() (uint32, bool) {
	if len(r.data)-r.pos < 4 {
		return 0, false
	}
	value := binary.BigEndian.Uint32(r.data[r.pos:])
	r.pos += 4
	return value, true
}

func (r *sshReader) string() ([]byte, bool) {
	length, ok := r.uint32()
	if !ok || uint64(length) > uint64(len(r.data)-r.pos) {
		return nil, false
	}
	value := r.data[r.pos : r.pos+int(length)]
	r.pos += int(length)
	return value, true
}

func (r *sshReader) rest() []byte { return r.data[r.pos:] }

// sshPublicBlob is the 32 raw bytes of an ssh-ed25519 public blob with nothing after them, or nil.
// Also used by formats.go, which reads the same blob in a public key line.
func sshPublicBlob(blob []byte) []byte {
	reader := &sshReader{data: blob}
	if kind, _ := reader.string(); string(kind) != sshEd25519 {
		return nil
	}
	raw, _ := reader.string()
	if len(raw) != rawLen || len(reader.rest()) != 0 {
		return nil
	}
	return raw
}

// refusePrivate is a refusal of a private key. Keyid is empty and the reason never quotes the
// input: a private key must not reach a log.
func refusePrivate(reason string) error {
	return &Error{Kind: KindMalformedKey, Message: "The OpenSSH private key was refused: " + reason}
}

// FromOpenSSH loads an unencrypted OpenSSH Ed25519 private key, as ssh-keygen writes it.
//
// The text is the armored key, LF line endings, with or without the final newline. The key must
// be the only one in the file, its check integers must agree, its padding must be 1, 2, 3, ...,
// and its public key must match in both places it is stored and must be the one its seed derives.
// Anything else is an *Error of kind MalformedKey that never carries any part of the key.
//
// Use a key dedicated to fiki and never loaded into ssh-agent. Signatures do not cross between
// protocols -- every base SignRequest and SignResponse build begins with a double quote, SSH user
// authentication signs data beginning with a length-prefixed session identifier (RFC 4252 section
// 7), and SSHSIG signs data beginning "SSHSIG" -- but an agent signs whatever bytes it is asked
// to, so anyone able to use a forwarded agent could sign fiki requests with a login key. The
// separation is a property of SignRequest, not of the key: Key.Sign signs any bytes.
func FromOpenSSH(text string) (*Key, error) {
	seed, err := readOpenSSH(text)
	if err != nil {
		return nil, err
	}
	return &Key{private: ed25519.NewKeyFromSeed(seed)}, nil
}

func readOpenSSH(text string) ([]byte, error) {
	if utf8.RuneCountInString(text) > maxPrivateChars {
		return nil, refusePrivate("it is over 4096 characters.")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 || lines[0] != opensshBegin || lines[len(lines)-1] != opensshEnd {
		return nil, refusePrivate(`it is not one "` + opensshBegin +
			`" block with LF line endings and nothing around it.`)
	}
	body := lines[1 : len(lines)-1]
	for _, line := range body {
		if line == "" || !b64stdText.MatchString(line) {
			return nil, refusePrivate("its body is not lines of standard base64.")
		}
	}
	blob := canonicalB64std(strings.Join(body, ""))
	if blob == nil {
		return nil, refusePrivate("its body is not canonical standard base64.")
	}
	if !bytes.HasPrefix(blob, []byte(opensshMagic)) {
		return nil, refusePrivate("it is not in the openssh-key-v1 format.")
	}
	reader := &sshReader{data: blob[len(opensshMagic):]}
	cipher, cipherOK := reader.string()
	kdf, _ := reader.string()
	kdfoptions, kdfoptionsOK := reader.string()
	if cipherOK && string(cipher) != "none" {
		return nil, refusePrivate("it is encrypted under a passphrase, and fiki reads only " +
			"unencrypted keys. Keep a dedicated key for fiki rather than removing the passphrase " +
			"from one used elsewhere.")
	}
	if count, _ := reader.uint32(); !cipherOK || string(kdf) != "none" || !kdfoptionsOK ||
		len(kdfoptions) != 0 || count != 1 {
		return nil, refusePrivate("its header is not that of exactly one unencrypted key.")
	}
	public, _ := reader.string()
	raw := sshPublicBlob(public)
	private, privateOK := reader.string()
	if raw == nil || !privateOK || len(reader.rest()) != 0 {
		return nil, refusePrivate("it is not exactly one ssh-ed25519 key with nothing after it.")
	}
	return privateSection(private, raw)
}

// privateSection is the seed from the private section, after every consistency check it carries.
func privateSection(private, raw []byte) ([]byte, error) {
	reader := &sshReader{data: private}
	check, checkOK := reader.uint32()
	again, againOK := reader.uint32()
	if len(private)%8 != 0 || !checkOK || !againOK || check != again {
		return nil, refusePrivate("its private section is misaligned or its check integers differ.")
	}
	kind, _ := reader.string()
	inner, _ := reader.string()
	secret, _ := reader.string()
	comment, commentOK := reader.string()
	if string(kind) != sshEd25519 || !bytes.Equal(inner, raw) || len(secret) != 2*rawLen {
		return nil, refusePrivate("its private section does not hold the key its public section names.")
	}
	seed := secret[:rawLen]
	derived := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !bytes.Equal(secret[rawLen:], raw) || !bytes.Equal(derived, raw) {
		return nil, refusePrivate("its seed does not derive the public key it is stored with.")
	}
	if !commentOK || !printableASCII(comment) {
		return nil, refusePrivate("its comment is not printable ASCII.")
	}
	padding := reader.rest()
	for i, b := range padding {
		if i >= 7 || int(b) != i+1 {
			return nil, refusePrivate("its padding is not 1, 2, 3, ... to the next eight-byte boundary.")
		}
	}
	return bytes.Clone(seed), nil
}

func printableASCII(data []byte) bool {
	for _, b := range data {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

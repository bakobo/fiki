package fiki

// The OpenSSH wire encodings an ssh-ed25519 public line carries (`this.i` @0mvgkwnl).

import (
	"encoding/base64"
	"encoding/binary"
	"regexp"
)

const sshEd25519 = "ssh-ed25519"

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

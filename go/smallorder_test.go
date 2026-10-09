package fiki

// Small-order Ed25519 keys are MalformedKey wherever they come from (`this.i` @8krqtpsu, tick
// 27eo). The points are derived here from the curve equation rather than copied from a blocklist,
// so the test and the check do not share a method: the check maps to Montgomery form and asks
// X25519, the test solves for the Edwards y coordinates directly.

import (
	"crypto/ed25519"
	"math/big"
	"testing"
)

var curveP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

func modP(x *big.Int) *big.Int { return new(big.Int).Mod(x, curveP) }

// encodeY is the 32-byte little-endian encoding of y with the sign bit of x set as asked.
func encodeY(y *big.Int, sign bool) []byte {
	out := make([]byte, 32)
	y.FillBytes(out)
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if sign {
		out[31] |= 0x80
	}
	return out
}

// smallOrderYs are the y coordinates of every point whose order divides 8. The identity is
// y = 1, order 2 is y = -1, order 4 is y = 0; an order-8 point P doubles to y = 0, and for
// a = -1 the doubling formula gives y(2P) = (y^2 + x^2) / (2 - y^2 + x^2), so x^2 = -y^2, which
// with the curve equation -x^2 + y^2 = 1 + d x^2 y^2 gives d y^4 + 2 y^2 - 1 = 0, that is
// y^2 = (-1 +- sqrt(1 + d)) / d.
func smallOrderYs(t *testing.T) []*big.Int {
	t.Helper()
	d := modP(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), curveP)))
	ys := []*big.Int{big.NewInt(1), modP(big.NewInt(-1)), big.NewInt(0)}
	root := new(big.Int).ModSqrt(modP(new(big.Int).Add(big.NewInt(1), d)), curveP)
	if root == nil {
		t.Fatal("1 + d has no square root, so the derivation is wrong")
	}
	dInverse := new(big.Int).ModInverse(d, curveP)
	for _, r := range []*big.Int{root, new(big.Int).Neg(root)} {
		y2 := modP(new(big.Int).Mul(new(big.Int).Sub(r, big.NewInt(1)), dInverse))
		if y := new(big.Int).ModSqrt(y2, curveP); y != nil {
			ys = append(ys, y, modP(new(big.Int).Neg(y)))
		}
	}
	if len(ys) != 5 {
		t.Fatalf("expected five small-order y coordinates, derived %d", len(ys))
	}
	return ys
}

// smallOrderKeys is every encoding of a small-order point: each y with either sign bit, and the
// non-canonical y + p wherever that still fits in 255 bits.
func smallOrderKeys(t *testing.T) [][]byte {
	var keys [][]byte
	for _, y := range smallOrderYs(t) {
		candidates := []*big.Int{y}
		if alias := new(big.Int).Add(y, curveP); alias.BitLen() <= 255 {
			candidates = append(candidates, alias)
		}
		for _, c := range candidates {
			keys = append(keys, encodeY(c, false), encodeY(c, true))
		}
	}
	return keys
}

func TestTheIdentityKeyForgeryIsRealInTheStandardLibrary(t *testing.T) {
	// Why the check exists: crypto/ed25519 itself accepts this over any message.
	identity := append([]byte{1}, make([]byte, 31)...)
	forged := append([]byte{1}, make([]byte, 63)...)
	if !ed25519.Verify(identity, []byte("anything at all"), forged) {
		t.Skip("crypto/ed25519 no longer accepts the identity-key forgery")
	}
}

func TestSmallOrderKeysAreDetected(t *testing.T) {
	keys := smallOrderKeys(t)
	if len(keys) != 14 {
		t.Fatalf("expected 14 encodings, got %d", len(keys))
	}
	for _, key := range keys {
		if !smallOrder(key) {
			t.Errorf("%x is of small order and was not detected", key)
		}
	}
	for _, seed := range []byte{0, 2, 3, 7} {
		key, err := FromSeed(append([]byte{seed}, make([]byte, 31)...))
		if err != nil {
			t.Fatal(err)
		}
		if smallOrder(key.private.Public().(ed25519.PublicKey)) {
			t.Errorf("a real key from seed %d was taken for a small-order one", seed)
		}
	}
}

func TestSmallOrderKeysAreMalformedOnEveryPath(t *testing.T) {
	forged := "sig=:" + b64std(append([]byte{1}, make([]byte, 63)...)) + ":"
	for _, key := range smallOrderKeys(t) {
		raw := b64url.EncodeToString(key)
		headers := map[string]string{"Signature-Input": `sig=("@method");keyid="` + raw + `"`, "Signature": forged}

		// A raw keyid.
		if _, err := verifyOptedOut("GET", urlQuery, headers, VerifyOptions{}); kindOf(t, err) != KindMalformedKey {
			t.Errorf("raw keyid %s: %v", raw, err)
		}
		// An expected AID, where the key's encoding is canonical enough to be one.
		aid := ToAID(key)
		if _, err := verifyOptedOut("GET", urlQuery, headers, VerifyOptions{ExpectedAID: String(aid)}); kindOf(t, err) != KindMalformedKey {
			t.Errorf("expected AID %s: %v", aid, err)
		}
		// A resolver's answer.
		headers["Signature-Input"] = `sig=("@method");keyid="` + keriAID + `"`
		resolve := func(string) ([]byte, error) { return key, nil }
		if _, err := verifyOptedOut("GET", urlQuery, headers, VerifyOptions{Resolve: resolve}); kindOf(t, err) != KindMalformedKey {
			t.Errorf("resolved key %x: %v", key, err)
		}
	}
}

package fiki

// A 32-byte key that is not the canonical encoding of a point on the curve is MalformedKey, on the
// keyid path and the resolver path, before any signature check (`this.i` @8krqtpsu, tick 27eo).
// The test classifies y with Euler's criterion; the check uses a modular square root.

import (
	"crypto/ed25519"
	"math/big"
	"testing"
)

// onCurve reports whether some x satisfies -x^2 + y^2 = 1 + d x^2 y^2 for this y, that is
// whether (y^2 - 1) / (d y^2 + 1) is a square mod p, by Euler's criterion.
func onCurve(y *big.Int) bool {
	d := modP(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), curveP)))
	y2 := modP(new(big.Int).Mul(y, y))
	num := modP(new(big.Int).Sub(y2, big.NewInt(1)))
	den := modP(new(big.Int).Add(new(big.Int).Mul(d, y2), big.NewInt(1)))
	x2 := modP(new(big.Int).Mul(num, new(big.Int).ModInverse(den, curveP)))
	if x2.Sign() == 0 {
		return true
	}
	exp := new(big.Int).Rsh(new(big.Int).Sub(curveP, big.NewInt(1)), 1)
	return new(big.Int).Exp(x2, exp, curveP).Cmp(big.NewInt(1)) == 0
}

func TestNonCanonicalOrOffCurveKeysAreMalformed(t *testing.T) {
	var offCurve, aliasOfOnCurve *big.Int
	for k := int64(2); k < 19 && (offCurve == nil || aliasOfOnCurve == nil); k++ {
		y := big.NewInt(k)
		if !onCurve(y) && offCurve == nil {
			offCurve = y
		}
		if onCurve(y) && aliasOfOnCurve == nil {
			aliasOfOnCurve = new(big.Int).Add(y, curveP) // y >= p, naming a large-order point
		}
	}
	if offCurve == nil || aliasOfOnCurve == nil {
		t.Fatal("no candidates among y = 2..18")
	}
	cases := map[string][]byte{
		"an off-curve y":                      encodeY(offCurve, false),
		"y >= p naming a large-order point":   encodeY(aliasOfOnCurve, false),
		"x = 0 with the sign bit set (y = 1)": encodeY(big.NewInt(1), true),
	}
	forged := "sig=:" + b64std(make([]byte, 64)) + ":"
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			raw := b64url.EncodeToString(key)
			headers := map[string]string{"Signature-Input": `sig=("@method");keyid="` + raw + `"`, "Signature": forged}
			if _, err := VerifyRequest("GET", urlQuery, headers, VerifyOptions{}); kindOf(t, err) != KindMalformedKey {
				t.Errorf("keyid path: %v", err)
			}
			headers["Signature-Input"] = `sig=("@method");keyid="` + keriAID + `"`
			resolve := func(string) ([]byte, error) { return key, nil }
			if _, err := VerifyRequest("GET", urlQuery, headers, VerifyOptions{Resolve: resolve}); kindOf(t, err) != KindMalformedKey {
				t.Errorf("resolver path: %v", err)
			}
		})
	}
	// Real keys still pass.
	for _, seed := range []byte{0, 2, 3, 7} {
		key, _ := FromSeed(append([]byte{seed}, make([]byte, 31)...))
		if !canonicalPoint(key.private.Public().(ed25519.PublicKey)) {
			t.Errorf("seed %d's key is not taken for a canonical point", seed)
		}
	}
}

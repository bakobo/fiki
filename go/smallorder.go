package fiki

// Small-order Ed25519 keys (`this.i` @8krqtpsu, tick 27eo).
//
// crypto/ed25519 accepts the signature 0x01 || 0^63 under the key 0x01 || 0^31, the identity
// point, over any message: [S]B = R + [k]A holds trivially when A is the identity and S is zero,
// and every point whose order divides 8 opens a shortcut of the same family. fiki refuses such a
// key as MalformedKey before any signature is checked.

import (
	"crypto/ecdh"
	"math/big"
)

var (
	fieldPrime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	bigOne     = big.NewInt(1)

	// Any X25519 private key works as the probe: RFC 7748 clamps every scalar to a multiple of 8
	// below 2^255, so the shared secret is all zeros exactly when the peer point's order divides
	// 8, and Go's ECDH returns an error exactly then. All-zero bytes is a fine key for a probe
	// whose output is never used.
	smallOrderProbe, _ = ecdh.X25519().NewPrivateKey(make([]byte, 32))
)

// smallOrder reports whether a 32-byte Ed25519 public key encodes a point whose order divides 8,
// in any encoding, canonical or not. The Edwards y coordinate maps to the Montgomery u = (1 + y) /
// (1 - y), and X25519 against the probe answers the question; y = 1, the identity, has no u and is
// caught directly. The sign bit of x does not change a point's order, so it is ignored.
func smallOrder(key []byte) bool {
	littleEndian := make([]byte, 32)
	for i := range littleEndian {
		littleEndian[31-i] = key[i]
	}
	littleEndian[0] &= 0x7f // the sign bit of x, now the top bit of the big-endian form
	y := new(big.Int).Mod(new(big.Int).SetBytes(littleEndian), fieldPrime)

	denominator := new(big.Int).Mod(new(big.Int).Sub(bigOne, y), fieldPrime)
	if denominator.Sign() == 0 {
		return true
	}
	u := new(big.Int).Add(bigOne, y)
	u.Mul(u, new(big.Int).ModInverse(denominator, fieldPrime))
	u.Mod(u, fieldPrime)

	encoded := u.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	peer, _ := ecdh.X25519().NewPublicKey(encoded) // 32 bytes, so this cannot fail
	_, err := smallOrderProbe.ECDH(peer)
	return err != nil
}

// edwardsD is the curve constant d = -121665 / 121666 mod p (RFC 8032 section 5.1).
var edwardsD = new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665),
	new(big.Int).ModInverse(big.NewInt(121666), fieldPrime)), fieldPrime)

// canonicalPoint reports whether a 32-byte key is the canonical encoding of a point on the curve
// (RFC 8032 section 5.1.3): y below p, some x with -x^2 + y^2 = 1 + d x^2 y^2, and the sign bit
// clear when that x is 0. crypto/ed25519 refuses the rest only by failing every signature, which
// would report a defect in the key as a forgery (@8krqtpsu).
func canonicalPoint(key []byte) bool {
	bigEndian := make([]byte, 32)
	for i := range bigEndian {
		bigEndian[31-i] = key[i]
	}
	sign := bigEndian[0]&0x80 != 0
	bigEndian[0] &= 0x7f
	y := new(big.Int).SetBytes(bigEndian)
	if y.Cmp(fieldPrime) >= 0 {
		return false
	}
	y2 := new(big.Int).Mul(y, y)
	numerator := new(big.Int).Sub(y2, bigOne)
	denominator := new(big.Int).Add(new(big.Int).Mul(edwardsD, y2), bigOne)
	x2 := new(big.Int).Mul(numerator, new(big.Int).ModInverse(denominator.Mod(denominator, fieldPrime), fieldPrime))
	x2.Mod(x2, fieldPrime)
	if x2.Sign() == 0 {
		return !sign
	}
	return new(big.Int).ModSqrt(x2, fieldPrime) != nil
}

// subgroupOrder is L, the order of Ed25519's prime-order subgroup (RFC 8032 section 5.1), written
// as that section writes it.
var subgroupOrder = func() *big.Int {
	tail, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	return tail.Add(tail, new(big.Int).Lsh(bigOne, 252))
}()

// extended is a point in RFC 8032 section 5.1.4's extended coordinates, X Y Z T with x = X/Z,
// y = Y/Z and x y = T/Z.
type extended struct{ x, y, z, t *big.Int }

func fieldMul(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), fieldPrime) }

// add is RFC 8032 section 5.1.4's addition, complete on the curve, so it doubles too.
func (a extended) add(b extended) extended {
	e1 := fieldMul(new(big.Int).Sub(a.y, a.x), new(big.Int).Sub(b.y, b.x))
	h1 := fieldMul(new(big.Int).Add(a.y, a.x), new(big.Int).Add(b.y, b.x))
	c := fieldMul(fieldMul(a.t, b.t), new(big.Int).Lsh(edwardsD, 1))
	d := fieldMul(new(big.Int).Lsh(a.z, 1), b.z)
	e, f := new(big.Int).Sub(h1, e1), new(big.Int).Sub(d, c)
	g, h := new(big.Int).Add(d, c), new(big.Int).Add(h1, e1)
	return extended{fieldMul(e, f), fieldMul(g, h), fieldMul(f, g), fieldMul(e, h)}
}

// primeOrder reports whether [L]P is the identity for a key canonicalPoint has already accepted, so
// that P lies in the prime-order subgroup (this.i @37rktct3). A point of small order is not caught
// here, since the identity is one; smallOrder runs first. What this adds is the mixed-order point, a
// subgroup point plus a torsion component, which libsodium's crypto_core_ed25519_is_valid_point
// refuses and keripy follows.
func primeOrder(key []byte) bool {
	bigEndian := make([]byte, 32)
	for i := range bigEndian {
		bigEndian[31-i] = key[i]
	}
	odd := bigEndian[0]&0x80 != 0
	bigEndian[0] &= 0x7f
	y := new(big.Int).SetBytes(bigEndian)
	y2 := fieldMul(y, y)
	denominator := new(big.Int).Add(fieldMul(edwardsD, y2), bigOne)
	x := new(big.Int).ModSqrt(fieldMul(new(big.Int).Sub(y2, bigOne), new(big.Int).ModInverse(denominator, fieldPrime)), fieldPrime)
	if (x.Bit(0) == 1) != odd {
		x.Sub(fieldPrime, x)
	}
	total := extended{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}
	step := extended{x, y, big.NewInt(1), fieldMul(x, y)}
	for i := 0; i < subgroupOrder.BitLen(); i++ {
		if subgroupOrder.Bit(i) == 1 {
			total = total.add(step)
		}
		step = step.add(step)
	}
	return total.x.Sign() == 0 && total.y.Cmp(total.z) == 0
}

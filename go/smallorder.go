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

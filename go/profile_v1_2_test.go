package fiki

// What KERI profile version 1.2 asks of the Go port beyond 1.1 (`this.i` @37rktct3, @84nt4je0),
// mirroring fiki-py's test_profile_v1_2.py.
//
// Two rules, each a library behaviour rather than vector data. Under a resolver, where the keyid is
// an AID, a B keyid's key is the prefix's and must lie in the prime-order subgroup, and an AID is
// any of keripy's PreDex prefix codes (@37rktct3). Content no header announced is refused at the
// body stage, after the signature and freshness checks, so a message with two defects gets one
// code whichever kind of verifier reads it (@84nt4je0).
//
// The mixed-order oracle here builds its torsion point from the curve equation (smallorder_test.go's
// order-8 y coordinates) and adds in affine coordinates, not the extended ones the library uses, so
// a wrong check and a wrong oracle cannot agree by sharing a method.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

// cesr is CESR's arithmetic: zero bytes in front to a multiple of three, base64url, and the code in
// place of the characters those bytes became.
func cesr(code string, data []byte) string {
	pad := (3 - len(data)%3) % 3
	return code + base64.RawURLEncoding.EncodeToString(append(make([]byte, pad), data...))[pad:]
}

// --- a mixed-order key, built in affine coordinates ---

type affine struct{ x, y *big.Int }

var curveD = modP(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), curveP)))

func affineAdd(a, b affine) affine {
	t := modP(new(big.Int).Mul(new(big.Int).Mul(curveD, new(big.Int).Mul(a.x, b.x)), new(big.Int).Mul(a.y, b.y)))
	xNum := new(big.Int).Add(new(big.Int).Mul(a.x, b.y), new(big.Int).Mul(a.y, b.x))
	yNum := new(big.Int).Add(new(big.Int).Mul(a.y, b.y), new(big.Int).Mul(a.x, b.x))
	xDen := new(big.Int).ModInverse(modP(new(big.Int).Add(bigOne, t)), curveP)
	yDen := new(big.Int).ModInverse(modP(new(big.Int).Sub(bigOne, t)), curveP)
	return affine{modP(xNum.Mul(xNum, xDen)), modP(yNum.Mul(yNum, yDen))}
}

func (a affine) isIdentity() bool { return a.x.Sign() == 0 && a.y.Cmp(bigOne) == 0 }

// xFor solves the curve equation for x with the given parity.
func xFor(t *testing.T, y *big.Int, odd bool) *big.Int {
	t.Helper()
	y2 := modP(new(big.Int).Mul(y, y))
	x2 := modP(new(big.Int).Mul(new(big.Int).Sub(y2, bigOne),
		new(big.Int).ModInverse(modP(new(big.Int).Add(new(big.Int).Mul(curveD, y2), bigOne)), curveP)))
	x := new(big.Int).ModSqrt(x2, curveP)
	if x == nil {
		t.Fatalf("no x on the curve for y %v", y)
	}
	if (x.Bit(0) == 1) != odd {
		x = modP(new(big.Int).Neg(x))
	}
	return x
}

func decodeAffine(t *testing.T, raw []byte) affine {
	t.Helper()
	bigEndian := make([]byte, 32)
	for i := range bigEndian {
		bigEndian[31-i] = raw[i]
	}
	odd := bigEndian[0]&0x80 != 0
	bigEndian[0] &= 0x7f
	y := new(big.Int).SetBytes(bigEndian)
	return affine{xFor(t, y, odd), y}
}

func encodeAffine(p affine) []byte { return encodeY(p.y, p.x.Bit(0) == 1) }

func orderEight(t *testing.T) affine {
	t.Helper()
	for _, y := range smallOrderYs(t) {
		if y.Cmp(bigOne) == 0 {
			continue // the identity, whose order is 1
		}
		point := affine{xFor(t, y, false), y}
		sum, n := point, 1
		for !sum.isIdentity() {
			sum, n = affineAdd(sum, point), n+1
		}
		if n == 8 {
			return point
		}
	}
	t.Fatal("no point of order 8")
	return affine{}
}

func multiply(p affine, n *big.Int) affine {
	total := affine{big.NewInt(0), big.NewInt(1)}
	for i := n.BitLen() - 1; i >= 0; i-- {
		total = affineAdd(total, total)
		if n.Bit(i) == 1 {
			total = affineAdd(total, p)
		}
	}
	return total
}

// L, RFC 8032 section 5.1's order of the prime-order subgroup, written as that section writes it.
func oracleL() *big.Int {
	tail, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	return tail.Add(tail, new(big.Int).Lsh(bigOne, 252))
}

type v12 struct {
	key    *Key
	mixed  []byte
	bMixed string
	bWeak  string
	eAID   string
}

func v12Fixture(t *testing.T) v12 {
	t.Helper()
	key := testKey(t)
	public := []byte(key.private.Public().(ed25519.PublicKey))
	mixed := encodeAffine(affineAdd(decodeAffine(t, public), orderEight(t)))
	digest := sha256.Sum256([]byte("a transferable AID"))
	return v12{
		key:    key,
		mixed:  mixed,
		bMixed: cesr("B", mixed),
		bWeak:  cesr("B", append([]byte{1}, make([]byte, 31)...)),
		eAID:   cesr("E", digest[:]),
	}
}

func never(t *testing.T) Resolver {
	return func(keyid string) ([]byte, error) {
		t.Errorf("the resolver was asked about %s", keyid)
		return nil, nil
	}
}

func signV12(t *testing.T, key *Key, keyid string, body []byte, headers map[string]string) map[string]string {
	t.Helper()
	signed, err := SignRequest(key, "POST", urlQuery, headers, SignOptions{Body: body, Created: signedAt, Keyid: keyid})
	if err != nil {
		t.Fatal(err)
	}
	return merged(headers, signed)
}

func verifyV12(headers map[string]string, opts VerifyOptions) (*Verdict, error) {
	if opts.MaxAge == nil {
		opts.MaxAge = maxAge(300)
	}
	if opts.Now == 0 {
		opts.Now = signedAt
	}
	opts.AnyAuthority = true
	if opts.Minimum == nil {
		opts.NoMinimum = true
	}
	return VerifyRequest("POST", urlQuery, headers, opts)
}

func TestTheOracleKeyIsOnTheCurveAndNotInThePrimeOrderSubgroup(t *testing.T) {
	f := v12Fixture(t)
	point := decodeAffine(t, f.mixed)
	if !canonicalPoint(f.mixed) || smallOrder(f.mixed) {
		t.Fatal("the mixed-order key should be a canonical point of large order")
	}
	if multiply(point, oracleL()).isIdentity() {
		t.Fatal("[L]P is the identity, so the oracle key is in the prime-order subgroup")
	}
	honest := decodeAffine(t, []byte(f.key.private.Public().(ed25519.PublicKey)))
	if !multiply(honest, oracleL()).isIdentity() {
		t.Fatal("an honest key's [L]P should be the identity")
	}
}

// --- B keyids under a resolver: the prefix's key, never the resolver's (@37rktct3) ---

func TestABKeyidIsVerifiedFromItsPrefixWithoutAskingTheResolver(t *testing.T) {
	f := v12Fixture(t)
	verdict, err := verifyV12(signV12(t, f.key, f.key.AID(), testBody, nil), VerifyOptions{Body: testBody, Resolve: never(t)})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Keyid != f.key.AID() || verdict.AID != f.key.AID() {
		t.Errorf("verdict = %+v", verdict)
	}
}

func TestAMixedOrderBKeyidIsMalformedUnderAResolver(t *testing.T) {
	f := v12Fixture(t)
	_, err := verifyV12(signV12(t, f.key, f.bMixed, testBody, nil), VerifyOptions{Body: testBody, Resolve: never(t)})
	if kindOf(t, err) != KindMalformedKey {
		t.Fatalf("expected MalformedKey, got %v", err)
	}
	if err.(*Error).Keyid != f.bMixed {
		t.Errorf("keyid = %q", err.(*Error).Keyid)
	}
}

func TestAWeakBKeyidIsMalformedBeforeTheExpectedKeyidIsCompared(t *testing.T) {
	f := v12Fixture(t)
	for name, keyid := range map[string]string{"small-order": f.bWeak, "mixed-order": f.bMixed} {
		t.Run(name, func(t *testing.T) {
			_, err := verifyV12(signV12(t, f.key, keyid, testBody, nil),
				VerifyOptions{Body: testBody, Resolve: never(t), ExpectedKeyid: String(f.eAID)})
			if kindOf(t, err) != KindMalformedKey {
				t.Fatalf("expected MalformedKey, got %v", err)
			}
		})
	}
}

func TestAMixedOrderKeyFromAResolverIsMalformed(t *testing.T) {
	f := v12Fixture(t)
	resolve := func(keyid string) ([]byte, error) {
		if keyid == f.eAID {
			return f.mixed, nil
		}
		return nil, nil
	}
	_, err := verifyV12(signV12(t, f.key, f.eAID, testBody, nil), VerifyOptions{Body: testBody, Resolve: resolve})
	if kindOf(t, err) != KindMalformedKey {
		t.Fatalf("expected MalformedKey, got %v", err)
	}
}

func TestAMixedOrderRawKeyidIsStillFikisOwnLensAndNotRefusedForItsOrder(t *testing.T) {
	// vectors_format 4 pins acceptance of a mixed-order raw keyid (@5r75ff4m); only an AID's key
	// must lie in the subgroup, so this one reaches the signature check.
	f := v12Fixture(t)
	keyid := base64.RawURLEncoding.EncodeToString(f.mixed)
	_, err := verifyV12(signV12(t, f.key, keyid, testBody, nil), VerifyOptions{Body: testBody})
	if kindOf(t, err) != KindSignatureMismatch {
		t.Fatalf("expected SignatureMismatch, got %v", err)
	}
}

// --- an AID is any of keripy's PreDex codes (@37rktct3) ---

var predex = map[string]int{
	"B": 32, "D": 32, "E": 32, "F": 32, "G": 32, "H": 32, "I": 32,
	"0D": 64, "0E": 64, "0F": 64, "0G": 64,
	"1AAA": 33, "1AAB": 33, "1AAI": 33, "1AAJ": 33,
	"1AAC": 57, "1AAD": 57, "1AAE": 114,
}

func TestEveryPreDexCodeSpellsAWellFormedAID(t *testing.T) {
	for code, size := range predex {
		t.Run(code, func(t *testing.T) {
			digest := sha512.Sum512([]byte(code))
			keyid := cesr(code, append(digest[:], digest[:]...)[:size])
			if !wellFormedAID(keyid) {
				t.Errorf("%s is not well formed", keyid)
			}
			if wellFormedAID(keyid[:len(keyid)-1]) || wellFormedAID(keyid+"A") {
				t.Errorf("a keyid of the wrong length is well formed")
			}
		})
	}
}

func TestOtherCodesAndNonCanonicalSpellingsAreNotAIDs(t *testing.T) {
	for name, keyid := range map[string]string{
		"code-A":       "A" + strings.Repeat("A", 43),
		"code-J":       "J" + strings.Repeat("A", 43),
		"code-0A":      "0A" + strings.Repeat("A", 86),
		"code-1AAF":    "1AAF" + strings.Repeat("A", 44),
		"1AAD-short":   "1AAD" + strings.Repeat("A", 75),
		"0D-pad-bit-1": "0D" + "g" + strings.Repeat("A", 85),
		"0D-pad-bit-2": "0D" + "Q" + strings.Repeat("A", 85),
		"not-base64":   "1AAB" + strings.Repeat("!", 44),
		"empty":        "",
		"short-code":   "1AA",
		"line-break":   "E" + strings.Repeat("A", 21) + "\n" + strings.Repeat("A", 21),
	} {
		if wellFormedAID(keyid) {
			t.Errorf("%s: %q should not be well formed", name, keyid)
		}
	}
}

func TestAnEd448TransferableKeyidWithNoKeyStateIsAnUnknownKey(t *testing.T) {
	f := v12Fixture(t)
	raw := make([]byte, 57)
	for i := range raw {
		raw[i] = byte(i)
	}
	keyid := cesr("1AAD", raw)
	_, err := verifyV12(signV12(t, f.key, keyid, testBody, nil), VerifyOptions{Body: testBody,
		Resolve: func(string) ([]byte, error) { return nil, nil }})
	if kindOf(t, err) != KindUnknownKey {
		t.Fatalf("expected UnknownKey, got %v", err)
	}
}

func otherNonTransferableKeyid(code string, size int) string {
	raw := []byte{2}
	for i := 0; i < size-1; i++ {
		raw = append(raw, byte(i))
	}
	return cesr(code, raw)
}

func TestANonTransferableKeyidOtherThanBIsAnUnsupportedAlgorithm(t *testing.T) {
	f := v12Fixture(t)
	for code, size := range map[string]int{"1AAA": 33, "1AAC": 57, "1AAI": 33} {
		t.Run(code, func(t *testing.T) {
			keyid := otherNonTransferableKeyid(code, size)
			_, err := verifyV12(signV12(t, f.key, keyid, testBody, nil), VerifyOptions{Body: testBody, Resolve: never(t)})
			if kindOf(t, err) != KindUnsupportedAlgorithm {
				t.Fatalf("expected UnsupportedAlgorithm, got %v", err)
			}
		})
	}
}

func TestANonTransferableKeyidOtherThanTheExpectedOneIsUnknownFirst(t *testing.T) {
	f := v12Fixture(t)
	keyid := otherNonTransferableKeyid("1AAA", 33)
	_, err := verifyV12(signV12(t, f.key, keyid, testBody, nil),
		VerifyOptions{Body: testBody, Resolve: never(t), ExpectedKeyid: String(f.eAID)})
	if kindOf(t, err) != KindUnknownKey {
		t.Fatalf("expected UnknownKey, got %v", err)
	}
}

// --- content no header announced, at the body stage (@84nt4je0) ---

func TestAnUnannouncedUncoveredRequestBodyIsRefusedAtTheBodyStage(t *testing.T) {
	f := v12Fixture(t)
	headers := signV12(t, f.key, f.key.AID(), nil, nil)
	_, err := verifyV12(headers, VerifyOptions{Body: testBody, Resolve: never(t), Minimum: RequestMinimum})
	if kindOf(t, err) != KindInsufficientCoverage {
		t.Fatalf("expected InsufficientCoverage, got %v", err)
	}
}

func TestAnUnannouncedUncoveredRequestBodyComesAfterFreshness(t *testing.T) {
	f := v12Fixture(t)
	headers := signV12(t, f.key, f.key.AID(), nil, nil)
	_, err := verifyV12(headers, VerifyOptions{Body: testBody, Resolve: never(t), Minimum: RequestMinimum, Now: signedAt + 1000})
	if kindOf(t, err) != KindSignatureTooOld {
		t.Fatalf("expected SignatureTooOld, got %v", err)
	}
}

func TestAnUnannouncedUncoveredRequestBodyComesBeforeTheDigestIsParsed(t *testing.T) {
	// Nothing covers a digest here, so a malformed Content-Digest is never parsed: the body stage
	// refuses first.
	f := v12Fixture(t)
	headers := signV12(t, f.key, f.key.AID(), nil, map[string]string{"Content-Digest": "not a digest"})
	_, err := verifyV12(headers, VerifyOptions{Body: testBody, Resolve: never(t), Minimum: RequestMinimum})
	if kindOf(t, err) != KindInsufficientCoverage {
		t.Fatalf("expected InsufficientCoverage, got %v", err)
	}
}

func TestAnAnnouncedUncoveredRequestBodyIsStillRefusedAtTheCoveredList(t *testing.T) {
	f := v12Fixture(t)
	headers := signV12(t, f.key, f.key.AID(), nil, map[string]string{"Content-Length": "18"})
	_, err := verifyV12(headers, VerifyOptions{Resolve: never(t), Minimum: RequestMinimum, Now: signedAt + 1000})
	if kindOf(t, err) != KindInsufficientCoverage {
		t.Fatalf("expected InsufficientCoverage, got %v", err)
	}
}

func TestAnUncoveredResponseBodyIsRefusedAtTheCoveredListByItsContent(t *testing.T) {
	// A client holds the response's content before verifying it, so the covered-list check judges
	// it there, ahead of the signature (profile section 9).
	f := v12Fixture(t)
	request := &Request{Method: "GET", URL: urlQuery, Headers: map[string]string{}}
	headers, err := SignResponse(f.key, 200, request, nil, SignOptions{Created: signedAt, Keyid: f.key.AID()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyResponse(201, request, headers, VerifyOptions{Body: []byte(`{"done": true}`), MaxAge: maxAge(300),
		Now: signedAt, Resolve: never(t), ExpectedKeyid: String(f.key.AID()), Minimum: ResponseMinimum})
	if kindOf(t, err) != KindInsufficientCoverage {
		t.Fatalf("expected InsufficientCoverage, got %v", err)
	}
}

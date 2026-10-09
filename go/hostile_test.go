package fiki

// The three attacks a hostile reviewer reproduced against the js port, tried against this one,
// and the small-order encodings checked one by one (`this.i` @8krqtpsu).

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestANonEmptyBodyIsABodyUnderTheMinimum(t *testing.T) {
	// js missed an ArrayBuffer body because it checked .length. Go's Body is []byte only, so the
	// attack is the plain one: a body handed over with no covered content-digest.
	key := testKey(t)
	headers, err := SignRequest(key, "POST", urlQuery, nil, SignOptions{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifyOptedOut("POST", urlQuery, headers, VerifyOptions{Body: []byte("x"), Minimum: RequestMinimum})
	if kindOf(t, err) != KindInsufficientCoverage {
		t.Error("an uncovered body should be refused under the minimum")
	}
}

func TestLineBreaksInACoveredFieldAreRefusedOnTheRawValue(t *testing.T) {
	// js trimmed first, so "admin\r\n" verified as "admin". Only SP and HTAB are trimmed.
	key := testKey(t)
	signed, err := SignRequest(key, "GET", urlQuery, map[string]string{"X-Role": "admin"},
		SignOptions{Created: signedAt, Covered: []string{"@method", "@path", "@query", "x-role"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"admin\r\n", "\r\nadmin", "admin\x00", "admin\n"} {
		headers := merged(signed, map[string]string{"X-Role": value})
		_, err := verifyOptedOut("GET", urlQuery, headers, VerifyOptions{})
		if kindOf(t, err) != KindSignatureMismatch {
			t.Errorf("%q should be refused, got %v", value, err)
		}
		_, err = SignRequest(key, "GET", urlQuery, map[string]string{"X-Role": value},
			SignOptions{Covered: []string{"@method", "@path", "@query", "x-role"}})
		if kindOf(t, err) != KindSignatureMismatch {
			t.Errorf("signing %q should be refused, got %v", value, err)
		}
	}
	headers := merged(signed, map[string]string{"X-Role": " \tadmin\t "})
	if _, err := verifyOptedOut("GET", urlQuery, headers, VerifyOptions{}); err != nil {
		t.Errorf("SP and HTAB around a value are trimmed: %v", err)
	}
}

func TestEveryEncodingLibsodiumBlocksIsSmallOrder(t *testing.T) {
	// has_small_order compares the first 31 bytes and the last with its top bit cleared, against
	// seven entries: 0, 1, the two order-8 points, p - 1, p and p + 1. Each is tried with the sign
	// bit clear and set. The order-8 encodings are the ones this package's derivation prints.
	ff := strings.Repeat("ff", 30)
	for name, encoding := range map[string]string{
		"0 (order 4)":            strings.Repeat("00", 32),
		"1, the identity":        "01" + strings.Repeat("00", 31),
		"order 8, first":         "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"order 8, second":        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"p - 1 (order 2)":        "ec" + ff + "7f",
		"p, non-canonical 0":     "ed" + ff + "7f",
		"p + 1, non-canonical 1": "ee" + ff + "7f",
	} {
		key, err := hex.DecodeString(encoding)
		if err != nil {
			t.Fatal(err)
		}
		for _, sign := range []byte{0, 0x80} {
			signed := append([]byte{}, key...)
			signed[31] |= sign
			if !smallOrder(signed) {
				t.Errorf("%s with sign bit %x is not detected", name, sign)
			}
		}
	}
}

package fiki

import "testing"

// keyid is REQUIRED in the KERI profile, so under a minimum it is required even when an
// ExpectedAID decides the key (the rust port's hostile review on bakobo/fiki#6).
func TestAMinimumRequiresAKeyidEvenWithAnExpectedAID(t *testing.T) {
	key := testKey(t)
	base, err := SignatureBase("GET", urlQuery, nil, []string{"@method", "@path", "@query"}, SignatureParams{Created: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{
		"Signature-Input": "sig=" + string(base[len(base)-len(`("@method" "@path" "@query");created=1700000000`):]),
		"Signature":       "sig=:" + b64std(key.Sign(base)) + ":",
	}
	if _, err := verifyOptedOut("GET", urlQuery, headers, VerifyOptions{ExpectedAID: key.AID()}); err != nil {
		t.Fatalf("without a minimum, an expected AID needs no keyid: %v", err)
	}
	_, err = verifyOptedOut("GET", urlQuery, headers, VerifyOptions{ExpectedAID: key.AID(), Minimum: RequestMinimum})
	if kindOf(t, err) != KindMissingKey {
		t.Errorf("under a minimum, a missing keyid is MissingKey, got %v", err)
	}
}

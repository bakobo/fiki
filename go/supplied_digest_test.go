package fiki

import "testing"

// Hostile review of 365f522 on bakobo/fiki#6, item 4.
func TestASuppliedContentDigestMustMatchTheBody(t *testing.T) {
	key := testKey(t)
	lie := map[string]string{"Content-Digest": ContentDigest([]byte("another body"))}
	if _, err := SignRequest(key, "POST", urlQuery, lie, SignOptions{Body: testBody}); kindOf(t, err) != KindDigestMismatch {
		t.Error("SignRequest should refuse a digest its body contradicts")
	}
	if _, err := SignResponse(key, 200, nil, lie, SignOptions{Body: testBody}); kindOf(t, err) != KindDigestMismatch {
		t.Error("SignResponse should refuse a digest its body contradicts")
	}
	if _, err := SignResponse(key, 200, nil, map[string]string{"Content-Digest": "((("}, SignOptions{Body: testBody}); kindOf(t, err) != KindMalformedDigest {
		t.Error("an unparsable supplied digest is MalformedDigest")
	}
}

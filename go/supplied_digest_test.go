package fiki

import "testing"

// Hostile review of 365f522 on bakobo/fiki#6, item 4, and the 0.8.0 sweep's A7 and E5 (this.i
// @5zrf8gjk): a supplied digest the body does not support is the caller's mistake.
func TestASuppliedContentDigestMustMatchTheBody(t *testing.T) {
	key := testKey(t)
	lie := map[string]string{"Content-Digest": ContentDigest([]byte("another body"))}
	_, err := SignRequest(key, "POST", urlQuery, lie, SignOptions{Body: testBody})
	isInvalidOptions(t, err)
	_, err = SignResponse(key, 200, nil, lie, SignOptions{Body: testBody})
	isInvalidOptions(t, err)
	_, err = SignResponse(key, 200, nil, map[string]string{"Content-Digest": "((("}, SignOptions{Body: testBody})
	isInvalidOptions(t, err)
}

package fiki

import "testing"

// Hostile review of 365f522 on bakobo/fiki#6, item 3.
func TestNothingButAPortMayFollowAnIPLiteral(t *testing.T) {
	for _, rawURL := range []string{"https://[::1]evil:443/", "https://x[::1]/", "https://[::1]:443evil/"} {
		_, err := SignatureBase("GET", rawURL, nil, []string{"@authority"}, SignatureParams{Created: 1})
		if kindOf(t, err) != KindMissingComponent {
			t.Errorf("%s should have no buildable authority", rawURL)
		}
	}
}

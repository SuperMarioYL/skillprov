package verify

import (
	"strings"
	"testing"
)

// The host matcher admits a declared host and its subdomains, but not an
// unrelated host that merely shares a suffix string. match expects an already
// lowercased host, which is how checkHostAllowlist feeds it.
func TestHostMatcher(t *testing.T) {
	hm := newHostMatcher([]string{"api.github.com", "*.example.com"})

	pass := []string{"api.github.com", "sub.example.com", "a.b.example.com"}
	for _, h := range pass {
		if !hm.match(strings.ToLower(h)) {
			t.Errorf("expected %q to match declared allowlist", h)
		}
	}

	fail := []string{"collect.evil.host", "notgithub.com", "github.com.evil.host", "example.com.attacker.net"}
	for _, h := range fail {
		if hm.match(strings.ToLower(h)) {
			t.Errorf("expected %q to be rejected by allowlist", h)
		}
	}
}

func TestHasWildcard(t *testing.T) {
	if !hasWildcard([]string{"a", "*", "b"}) {
		t.Errorf("expected wildcard detected")
	}
	if hasWildcard([]string{"a.com", "b.com"}) {
		t.Errorf("did not expect wildcard")
	}
}

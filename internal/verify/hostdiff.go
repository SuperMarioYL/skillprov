package verify

import (
	"strings"

	"github.com/SuperMarioYL/skillprov/internal/manifest"
	"github.com/SuperMarioYL/skillprov/internal/scan"
)

// checkHostAllowlist enforces the declared network HOST allowlist at value
// granularity. v0.1 reduced network to a single boolean, so a skill that
// declared network:{hosts:[api.github.com]} could quietly fetch evil.host and
// still verify green. As of v0.2, when the manifest declares a finite host
// allowlist (no "*" wildcard), every observed host must appear in it; any
// residual host is itself an undeclared capability and rejects the skill.
//
// A wildcard "*" host keeps the permissive path for skills that intentionally
// declared open network access — there is nothing to diff against.
func checkHostAllowlist(m *manifest.CapabilityManifest, res *scan.Result, v *Verdict) {
	allow := m.Capabilities.Network.Hosts
	// No finite allowlist to enforce: net is "none" (no hosts) or a wildcard.
	if m.Capabilities.Network.None || len(allow) == 0 || hasWildcard(allow) {
		return
	}

	allowed := newHostMatcher(allow)
	seen := map[string]bool{}
	for _, hit := range res.ObservedHostHits() {
		host := strings.ToLower(strings.TrimSuffix(hit.Host, "."))
		if host == "" || allowed.match(host) {
			continue
		}
		// Report only the first sighting of each off-allowlist host.
		if seen[host] {
			continue
		}
		seen[host] = true
		v.UndeclaredHosts = append(v.UndeclaredHosts, scan.HostHit{
			Host: host, File: hit.File, Line: hit.Line,
		})
	}
}

// checkEnvAllowlist enforces the declared ENV-VAR allowlist at value granularity.
// Mirrors the host diff: when the manifest declares a finite env allowlist (no
// "*" wildcard), an observed env var outside that set is undeclared and rejects.
func checkEnvAllowlist(m *manifest.CapabilityManifest, res *scan.Result, v *Verdict) {
	allow := m.Capabilities.Env
	if len(allow) == 0 || hasWildcard(allow) {
		return
	}

	allowed := map[string]bool{}
	for _, e := range allow {
		allowed[e] = true
	}
	seen := map[string]bool{}
	for _, hit := range res.ObservedEnvHits() {
		if hit.Name == "" || allowed[hit.Name] || seen[hit.Name] {
			continue
		}
		seen[hit.Name] = true
		v.UndeclaredEnv = append(v.UndeclaredEnv, scan.EnvHit{
			Name: hit.Name, File: hit.File, Line: hit.Line,
		})
	}
}

// hasWildcard reports whether the declared allowlist contains the permissive "*".
func hasWildcard(list []string) bool {
	for _, s := range list {
		if s == "*" {
			return true
		}
	}
	return false
}

// hostMatcher matches an observed host against a declared allowlist. A declared
// entry matches the host itself and, treating the entry as a registrable suffix,
// any of its subdomains: declaring "github.com" admits "api.github.com" but not
// "notgithub.com". An explicit leading-dot or "*." entry is also supported.
type hostMatcher struct {
	exact   map[string]bool
	suffix  []string // normalized to ".example.com" form
}

func newHostMatcher(hosts []string) *hostMatcher {
	hm := &hostMatcher{exact: map[string]bool{}}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if h == "" {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			hm.suffix = append(hm.suffix, "."+strings.TrimPrefix(h, "*."))
			continue
		}
		if strings.HasPrefix(h, ".") {
			hm.suffix = append(hm.suffix, h)
			continue
		}
		hm.exact[h] = true
		hm.suffix = append(hm.suffix, "."+h)
	}
	return hm
}

func (hm *hostMatcher) match(host string) bool {
	if hm.exact[host] {
		return true
	}
	for _, s := range hm.suffix {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

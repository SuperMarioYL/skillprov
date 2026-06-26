package verify

import (
	"testing"

	"github.com/SuperMarioYL/skillprov/internal/manifest"
	"github.com/SuperMarioYL/skillprov/internal/scan"
)

// A finite declared exec allowlist must reject any observed command outside it,
// while leaving in-policy and wildcard cases clean. This is the value-level exec
// enforcement that closes the last class-level capability hole (v0.3).
func TestCheckExecAllowlist(t *testing.T) {
	mkRes := func(cmds ...string) *scan.Result {
		r := &scan.Result{Observed: map[scan.Capability][]scan.Evidence{}}
		for i, c := range cmds {
			r.RecordExecHitForTest(c, "scripts/run.sh", i+1)
		}
		return r
	}

	cases := []struct {
		name      string
		declared  []string
		observed  []string
		wantBad   []string // commands expected in UndeclaredExec
	}{
		{
			name:     "off-allowlist commands rejected",
			declared: []string{"git"},
			observed: []string{"git", "curl", "sh"},
			wantBad:  []string{"curl", "sh"},
		},
		{
			name:     "all in-policy clean",
			declared: []string{"git", "curl"},
			observed: []string{"git", "curl"},
			wantBad:  nil,
		},
		{
			name:     "wildcard declared is permissive",
			declared: []string{"*"},
			observed: []string{"curl", "rm", "sh"},
			wantBad:  nil,
		},
		{
			name:     "path-qualified declared matches bare observed",
			declared: []string{"/usr/bin/git"},
			observed: []string{"git"},
			wantBad:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &manifest.CapabilityManifest{
				Capabilities: manifest.Capabilities{Exec: tc.declared},
			}
			v := &Verdict{}
			checkExecAllowlist(m, mkRes(tc.observed...), v)

			gotBad := map[string]bool{}
			for _, x := range v.UndeclaredExec {
				gotBad[x.Command] = true
			}
			if len(gotBad) != len(tc.wantBad) {
				t.Fatalf("got undeclared %v, want %v", keys(gotBad), tc.wantBad)
			}
			for _, w := range tc.wantBad {
				if !gotBad[w] {
					t.Errorf("expected %q rejected, got %v", w, keys(gotBad))
				}
			}
		})
	}
}

// An undeclared exec class (no commands at all) is handled by the class-level diff,
// not this value-level check — so an empty allowlist is a no-op here.
func TestCheckExecAllowlistEmptyIsNoop(t *testing.T) {
	r := &scan.Result{Observed: map[scan.Capability][]scan.Evidence{}}
	r.RecordExecHitForTest("curl", "x.sh", 1)
	m := &manifest.CapabilityManifest{Capabilities: manifest.Capabilities{Exec: nil}}
	v := &Verdict{}
	checkExecAllowlist(m, r, v)
	if len(v.UndeclaredExec) != 0 {
		t.Errorf("empty allowlist should be a no-op, got %+v", v.UndeclaredExec)
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

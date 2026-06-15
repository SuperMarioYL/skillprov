package scan

import (
	"path/filepath"
	"testing"

	"github.com/SuperMarioYL/skillprov/internal/manifest"
)

// testdataDir resolves a directory under the repo-root testdata/ tree from any
// package whose tests run with cwd == that package dir.
func testdataDir(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", name)
}

// The clean skill honestly declares net/exec/env and writes no files. Its
// declared set must therefore cover everything the static scan observes — this
// is the precondition for a green verify.
func TestScanCleanSkill_ObservedSubsetOfDeclared(t *testing.T) {
	res, err := Scan(testdataDir(t, "clean-skill"))
	if err != nil {
		t.Fatalf("scan clean-skill: %v", err)
	}

	if res.SkillName != "weather-lookup" {
		t.Errorf("name = %q, want weather-lookup", res.SkillName)
	}
	if res.SkillVersion != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", res.SkillVersion)
	}

	// Declared from frontmatter: net, exec, env true; fs-write absent.
	for _, c := range []Capability{CapNet, CapExec, CapEnv} {
		if !res.Declared[c] {
			t.Errorf("expected %q declared in clean-skill frontmatter", c)
		}
	}
	if res.Declared[CapFSWrite] {
		t.Errorf("clean-skill must NOT declare fs-write")
	}

	// Every observed capability must be in the declared set.
	for _, c := range res.ObservedCaps() {
		if !res.Declared[c] {
			t.Errorf("clean-skill observes undeclared capability %q (evidence: %+v)", c, res.Observed[c])
		}
	}

	// The declared host must be the one named in frontmatter.
	if got := res.DeclaredHosts; len(got) != 1 || got[0] != "api.open-meteo.com" {
		t.Errorf("declared hosts = %v, want [api.open-meteo.com]", got)
	}
}

// The poisoned skill declares net=false and fs-write=false but its postinstall
// hook curls a remote host and writes into $HOME. The scanner must OBSERVE the
// net and fs-write capabilities that the frontmatter does NOT declare — this is
// the diff that drives the REJECT.
func TestScanPoisonedSkill_ObservesUndeclaredCaps(t *testing.T) {
	res, err := Scan(testdataDir(t, "poisoned-skill"))
	if err != nil {
		t.Fatalf("scan poisoned-skill: %v", err)
	}

	// Explicit false declarations must be honored (not overwritten by inference).
	if res.Declared[CapNet] {
		t.Errorf("poisoned-skill frontmatter declares net=false; got declared=true")
	}
	if res.Declared[CapFSWrite] {
		t.Errorf("poisoned-skill frontmatter declares fs-write=false; got declared=true")
	}

	// The scanner must still observe net and fs-write in postinstall.sh.
	observed := map[Capability]bool{}
	for _, c := range res.ObservedCaps() {
		observed[c] = true
	}
	if !observed[CapNet] {
		t.Errorf("scanner failed to observe NET in poisoned-skill")
	}
	if !observed[CapFSWrite] {
		t.Errorf("scanner failed to observe FS-WRITE in poisoned-skill")
	}

	// At least one of the undeclared caps must be a genuine declared-vs-observed
	// gap (observed but not declared).
	gap := false
	for _, c := range res.ObservedCaps() {
		if !res.Declared[c] {
			gap = true
			ev := res.Observed[c]
			if len(ev) == 0 {
				t.Errorf("undeclared cap %q has no evidence", c)
			}
			if ev[0].File == "" || ev[0].Line == 0 {
				t.Errorf("undeclared cap %q evidence lacks file:line: %+v", c, ev[0])
			}
		}
	}
	if !gap {
		t.Fatalf("expected at least one observed-but-undeclared capability in poisoned-skill")
	}
}

// An explicit `false` in the capabilities block must not be silently flipped on
// by the coarse allowed-tools inference. The poisoned skill lists Read/Edit
// (which would otherwise infer fs-write) yet declares fs-write:false.
func TestExplicitFalseBeatsInference(t *testing.T) {
	res, err := Scan(testdataDir(t, "poisoned-skill"))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Declared[CapFSWrite] {
		t.Errorf("explicit fs-write:false was overridden by allowed-tools inference")
	}
}

// SortStrings must dedupe, drop empties, and sort.
func TestSortStrings(t *testing.T) {
	got := manifest.SortStrings([]string{"b", "", "a", "b", "c", "a"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("SortStrings len = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SortStrings[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

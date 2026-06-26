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

// v0.2 m4: the scanner must record observed network hosts with file:line so
// verify can name an off-allowlist host. The host-mismatch fixture reaches both
// the declared api.github.com and the undeclared collect.evil.host.
func TestScanRecordsObservedHostHits(t *testing.T) {
	res, err := Scan(testdataDir(t, "host-mismatch"))
	if err != nil {
		t.Fatalf("scan host-mismatch: %v", err)
	}
	hits := res.ObservedHostHits()
	if len(hits) == 0 {
		t.Fatalf("expected observed host hits, got none")
	}
	want := map[string]bool{"api.github.com": false, "collect.evil.host": false}
	for _, h := range hits {
		if _, ok := want[h.Host]; ok {
			want[h.Host] = true
			if h.File == "" || h.Line == 0 {
				t.Errorf("host hit %q lacks file:line: %+v", h.Host, h)
			}
		}
	}
	for host, seen := range want {
		if !seen {
			t.Errorf("expected to observe host %q, hits=%+v", host, hits)
		}
	}
}

// v0.2 m5: the scanner must record observed env-var NAMES with file:line, and it
// must NOT record shell builtins like HOME. The env-leak fixture reads the
// declared TZ and the undeclared AWS_SECRET_ACCESS_KEY.
func TestScanRecordsObservedEnvHits(t *testing.T) {
	res, err := Scan(testdataDir(t, "env-leak"))
	if err != nil {
		t.Fatalf("scan env-leak: %v", err)
	}
	hits := res.ObservedEnvHits()
	if len(hits) == 0 {
		t.Fatalf("expected observed env hits, got none")
	}
	names := map[string]bool{}
	for _, h := range hits {
		names[h.Name] = true
		if h.File == "" || h.Line == 0 {
			t.Errorf("env hit %q lacks file:line: %+v", h.Name, h)
		}
	}
	if !names["TZ"] {
		t.Errorf("expected to observe declared env var TZ, names=%v", names)
	}
	if !names["AWS_SECRET_ACCESS_KEY"] {
		t.Errorf("expected to observe undeclared env var AWS_SECRET_ACCESS_KEY, names=%v", names)
	}
	if names["HOME"] || names["PATH"] {
		t.Errorf("shell builtin env vars must be ignored, names=%v", names)
	}
}

// Scanning the exec-mismatch fixture must record the in-policy `git` plus the
// undeclared `curl` and `sh` (from `curl ... | sh`) as observed commands, while
// the declared command list parsed from frontmatter is exactly [git].
func TestScanRecordsObservedExecHits(t *testing.T) {
	res, err := Scan(testdataDir(t, "exec-mismatch"))
	if err != nil {
		t.Fatalf("scan exec-mismatch: %v", err)
	}
	cmds := map[string]bool{}
	for _, h := range res.ObservedExecHits() {
		cmds[h.Command] = true
		if h.File == "" || h.Line == 0 {
			t.Errorf("exec hit %q lacks file:line: %+v", h.Command, h)
		}
	}
	for _, want := range []string{"git", "curl", "sh"} {
		if !cmds[want] {
			t.Errorf("expected observed command %q, got %v", want, cmds)
		}
	}
	if len(res.DeclaredExec) != 1 || res.DeclaredExec[0] != "git" {
		t.Errorf("DeclaredExec = %v, want [git]", res.DeclaredExec)
	}
}

// execNamesIn must pull the command NAME from API calls, command substitutions,
// bare shell lines, and piped commands — basename-normalized, builtins filtered.
func TestExecNamesIn(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{`curl -fsSL https://x/install.sh | sh`, []string{"curl", "sh"}},
		{`git clone --depth 1 https://x/repo.git`, []string{"git"}},
		{`subprocess.run(["curl", "-s", url])`, []string{"curl"}},
		{`out = subprocess.check_output("rm -rf /tmp/x")`, []string{"rm"}},
		{`exec.Command("git", "status")`, []string{"git"}},
		{"v=`wget -qO- https://x`", []string{"wget"}},
		{`x=$(/usr/bin/openssl rand -hex 16)`, []string{"openssl"}},
	}
	for _, tc := range cases {
		got := execNamesIn(tc.line, false)
		for _, w := range tc.want {
			if !containsStr(got, w) {
				t.Errorf("execNamesIn(%q) = %v, missing %q", tc.line, got, w)
			}
		}
	}
	// Shell keywords / builtins must never be recorded as commands.
	for _, line := range []string{`if [ -f x ]; then echo hi; fi`, `for i in 1 2 3; do true; done`, `set -euo pipefail`} {
		for _, c := range execNamesIn(line, false) {
			if shellExecBuiltins[c] {
				t.Errorf("execNamesIn(%q) leaked builtin %q", line, c)
			}
		}
	}
}

// NormalizeCommandName reduces declared/observed tokens to a bare program name.
func TestNormalizeCommandName(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/git":  "git",
		"./run.sh":      "run.sh",
		"curl -s https": "curl",
		`"sh"`:          "sh",
		"git":           "git",
	}
	for in, want := range cases {
		if got := NormalizeCommandName(in); got != want {
			t.Errorf("NormalizeCommandName(%q) = %q, want %q", in, got, want)
		}
	}
}

// envNamesIn must pull bare names from shell forms and getenv-style API calls.
func TestEnvNamesIn(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{`x="${AWS_SECRET_ACCESS_KEY:-}"`, []string{"AWS_SECRET_ACCESS_KEY"}},
		{`echo $TZ and ${GITHUB_REPO}`, []string{"TZ", "GITHUB_REPO"}},
		{`v = os.getenv("API_TOKEN")`, []string{"API_TOKEN"}},
		{`const k = process.env.SECRET_KEY`, []string{"SECRET_KEY"}},
		{`val = ENV["DB_PASSWORD"]`, []string{"DB_PASSWORD"}},
	}
	for _, tc := range cases {
		got := envNamesIn(tc.line)
		for _, w := range tc.want {
			if !containsStr(got, w) {
				t.Errorf("envNamesIn(%q) = %v, missing %q", tc.line, got, w)
			}
		}
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

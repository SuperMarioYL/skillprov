// Package verify performs the three-stage check that defines skillsig's value:
//
//  1. content integrity — recompute every file's sha256 and compare against the
//     digests recorded in the signed manifest;
//  2. signature validity — confirm the detached ed25519 bundle signs exactly the
//     manifest as written;
//  3. capability conformance — re-scan the skill and diff observed capabilities
//     against declared ones, rejecting any capability the skill reaches for but
//     did not declare.
//
// A failure in any stage produces a REJECTED verdict with a human-readable
// reason, and the CLI exits non-zero.
package verify

import (
	"fmt"
	"sort"

	"github.com/SuperMarioYL/skillsig/internal/manifest"
	"github.com/SuperMarioYL/skillsig/internal/scan"
	"github.com/SuperMarioYL/skillsig/internal/signer"
)

// Verdict is the result of verifying a skill directory.
type Verdict struct {
	Pass    bool
	Reasons []string  // why it failed (empty when Pass)
	Checks  []string  // human-readable lines describing each stage's outcome

	// Undeclared lists the capabilities observed but not declared, with their
	// triggering evidence — this is what drives the headline REJECTED message.
	Undeclared map[scan.Capability][]scan.Evidence
}

// Run executes all three verification stages over dir.
func Run(dir string) (*Verdict, error) {
	v := &Verdict{Pass: true, Undeclared: map[scan.Capability][]scan.Evidence{}}

	m, err := manifest.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("load manifest: %w (run `skillsig manifest` first)", err)
	}

	// Stage 1: content integrity.
	if err := checkDigests(dir, m, v); err != nil {
		return nil, err
	}

	// Stage 2: signature.
	checkSignature(dir, m, v)

	// Stage 3: capability conformance.
	if err := checkCapabilities(dir, m, v); err != nil {
		return nil, err
	}

	return v, nil
}

// checkDigests recomputes file hashes and compares them to the manifest.
func checkDigests(dir string, m *manifest.CapabilityManifest, v *Verdict) error {
	current, err := manifest.DigestDir(dir)
	if err != nil {
		return err
	}
	var mismatched, missing, added []string

	for path, want := range m.Digest.Files {
		got, ok := current.Files[path]
		if !ok {
			missing = append(missing, path)
			continue
		}
		if got != want {
			mismatched = append(mismatched, path)
		}
	}
	for path := range current.Files {
		if _, ok := m.Digest.Files[path]; !ok {
			added = append(added, path)
		}
	}
	sort.Strings(mismatched)
	sort.Strings(missing)
	sort.Strings(added)

	if len(mismatched)+len(missing)+len(added) == 0 {
		v.Checks = append(v.Checks, fmt.Sprintf("digest: %d files match the signed content lock", len(m.Digest.Files)))
		return nil
	}
	v.Pass = false
	for _, p := range mismatched {
		v.Reasons = append(v.Reasons, "modified file (digest mismatch): "+p)
	}
	for _, p := range missing {
		v.Reasons = append(v.Reasons, "missing file declared in manifest: "+p)
	}
	for _, p := range added {
		v.Reasons = append(v.Reasons, "extra file not in signed manifest: "+p)
	}
	v.Checks = append(v.Checks, "digest: content lock FAILED")
	return nil
}

// checkSignature verifies the detached bundle over the canonical manifest.
func checkSignature(dir string, m *manifest.CapabilityManifest, v *Verdict) {
	bundle, err := signer.LoadBundle(dir)
	if err != nil {
		v.Pass = false
		v.Reasons = append(v.Reasons, "signature bundle missing or unreadable (run `skillsig sign`)")
		v.Checks = append(v.Checks, "signature: NO BUNDLE")
		return
	}
	payload, err := m.Canonical()
	if err != nil {
		v.Pass = false
		v.Reasons = append(v.Reasons, "could not canonicalize manifest for signature check")
		v.Checks = append(v.Checks, "signature: ERROR")
		return
	}
	if err := bundle.Verify(payload); err != nil {
		v.Pass = false
		v.Reasons = append(v.Reasons, "signature invalid: "+err.Error())
		v.Checks = append(v.Checks, "signature: INVALID")
		return
	}
	v.Checks = append(v.Checks, "signature: valid ed25519 over manifest")
}

// checkCapabilities re-scans the skill and rejects undeclared observed capabilities.
func checkCapabilities(dir string, m *manifest.CapabilityManifest, v *Verdict) error {
	res, err := scan.Scan(dir)
	if err != nil {
		return err
	}

	declared := declaredFromManifest(m)
	var undeclaredList []scan.Capability
	for _, c := range res.ObservedCaps() {
		if !declared[c] {
			v.Undeclared[c] = res.Observed[c]
			undeclaredList = append(undeclaredList, c)
		}
	}

	if len(undeclaredList) == 0 {
		v.Checks = append(v.Checks, "capabilities: observed set is a subset of declared")
		return nil
	}
	v.Pass = false
	sort.Slice(undeclaredList, func(i, j int) bool { return undeclaredList[i] < undeclaredList[j] })
	for _, c := range undeclaredList {
		ev := v.Undeclared[c]
		first := ev[0]
		v.Reasons = append(v.Reasons, fmt.Sprintf(
			"undeclared capability %q observed at %s:%d  ->  %s",
			c, first.File, first.Line, first.Snippet))
	}
	v.Checks = append(v.Checks, "capabilities: UNDECLARED capability detected")
	return nil
}

// declaredFromManifest reduces the manifest's capability block to the four-class
// boolean set the scanner observes against.
func declaredFromManifest(m *manifest.CapabilityManifest) map[scan.Capability]bool {
	d := map[scan.Capability]bool{}
	c := m.Capabilities
	if len(c.Network.Hosts) > 0 || !c.Network.None {
		d[scan.CapNet] = true
	}
	// Network.None==true with no hosts means net is explicitly NOT declared.
	if c.Network.None && len(c.Network.Hosts) == 0 {
		d[scan.CapNet] = false
	}
	if len(c.Filesystem.Write) > 0 {
		d[scan.CapFSWrite] = true
	}
	if len(c.Exec) > 0 {
		d[scan.CapExec] = true
	}
	if len(c.Env) > 0 {
		d[scan.CapEnv] = true
	}
	return d
}

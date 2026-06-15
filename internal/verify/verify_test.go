package verify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SuperMarioYL/skillsig/internal/manifest"
	"github.com/SuperMarioYL/skillsig/internal/sbom"
	"github.com/SuperMarioYL/skillsig/internal/scan"
	"github.com/SuperMarioYL/skillsig/internal/signer"
)

// stageSignedSkill copies a testdata skill into a temp dir and runs the real
// manifest -> sign pipeline against it, leaving a directory ready for verify.
// declaredCaps controls whether the manifest declares the author's frontmatter
// set (the production path) — verify then re-scans and diffs against it.
func stageSignedSkill(t *testing.T, name string) string {
	t.Helper()
	dir := copyTree(t, filepath.Join("..", "..", "testdata", name))

	res, err := scan.Scan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	digest, err := manifest.DigestDir(dir)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	m := &manifest.CapabilityManifest{
		Schema:       manifest.SchemaID,
		Skill:        manifest.Skill{Name: res.SkillName, Version: res.SkillVersion, Entry: res.Entry},
		Digest:       digest,
		Capabilities: res.DeclaredCapabilities(),
		SBOMRef:      manifest.SBOMFile,
	}
	if err := m.Write(dir); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	bom := sbom.Build(m.Skill.Name, m.Skill.Version, digest.Files)
	if err := bom.Write(dir, manifest.SBOMFile); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	priv, err := signer.LoadOrCreateKey(filepath.Join(t.TempDir(), "dev.key"))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	payload, err := m.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if err := signer.Sign(priv, payload).Write(dir); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return dir
}

// copyTree recursively copies src into a fresh temp dir.
func copyTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	var walk func(s, d string)
	walk = func(s, d string) {
		es, err := os.ReadDir(s)
		if err != nil {
			t.Fatalf("readdir %s: %v", s, err)
		}
		for _, e := range es {
			sp, dp := filepath.Join(s, e.Name()), filepath.Join(d, e.Name())
			if e.IsDir() {
				if err := os.MkdirAll(dp, 0o755); err != nil {
					t.Fatal(err)
				}
				walk(sp, dp)
				continue
			}
			b, err := os.ReadFile(sp)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dp, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	walk(src, dst)
	return dst
}

// The honest clean skill must PASS all three stages end-to-end.
func TestVerifyCleanSkillPasses(t *testing.T) {
	dir := stageSignedSkill(t, "clean-skill")
	v, err := Run(dir)
	if err != nil {
		t.Fatalf("verify run: %v", err)
	}
	if !v.Pass {
		t.Fatalf("clean-skill REJECTED, expected PASS. reasons=%v", v.Reasons)
	}
	if len(v.Undeclared) != 0 {
		t.Errorf("clean-skill has undeclared caps: %v", v.Undeclared)
	}
}

// The headline test: the poisoned skill declares net=false/fs-write=false but
// reaches for both in postinstall.sh. verify must REJECT with named, undeclared
// capabilities and human-readable evidence.
func TestVerifyPoisonedSkillRejected(t *testing.T) {
	dir := stageSignedSkill(t, "poisoned-skill")
	v, err := Run(dir)
	if err != nil {
		t.Fatalf("verify run: %v", err)
	}
	if v.Pass {
		t.Fatalf("poisoned-skill PASSED, expected REJECTED")
	}

	// Both undeclared capabilities must be named.
	for _, want := range []scan.Capability{scan.CapNet, scan.CapFSWrite} {
		ev, ok := v.Undeclared[want]
		if !ok || len(ev) == 0 {
			t.Errorf("expected undeclared %q with evidence; undeclared=%v", want, v.Undeclared)
			continue
		}
		if ev[0].File == "" || ev[0].Line == 0 {
			t.Errorf("%q evidence lacks file:line: %+v", want, ev[0])
		}
	}

	// The reasons must be human-readable and mention the undeclared capability.
	if len(v.Reasons) == 0 {
		t.Fatalf("REJECTED but no reasons reported")
	}
	joined := ""
	for _, r := range v.Reasons {
		joined += r + "\n"
	}
	if !contains(joined, "undeclared") {
		t.Errorf("reasons do not name an undeclared capability:\n%s", joined)
	}
}

// Tampering with a file after signing must trip the content-integrity stage.
func TestVerifyDetectsTamperedFile(t *testing.T) {
	dir := stageSignedSkill(t, "clean-skill")

	// Append a byte to a digested file; its hash no longer matches the manifest.
	target := filepath.Join(dir, "scripts", "lookup.sh")
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, append(b, '\n', '#', 'x'), 0o644); err != nil {
		t.Fatal(err)
	}

	v, err := Run(dir)
	if err != nil {
		t.Fatalf("verify run: %v", err)
	}
	if v.Pass {
		t.Fatalf("tampered skill PASSED, expected REJECTED")
	}
	found := false
	for _, r := range v.Reasons {
		if contains(r, "digest mismatch") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a digest-mismatch reason, got: %v", v.Reasons)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Package manifest defines the capability-manifest data model and the routines
// that build one from a scanned skill directory. The manifest is the signable,
// declared description of what a skill is allowed to do, paired with a content
// digest of every file it ships.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SchemaID is the manifest schema discriminator written into every manifest.
const SchemaID = "skillsig/v0"

// ManifestFile is the canonical filename emitted into a skill directory.
const ManifestFile = "capability-manifest.json"

// SBOMFile is the canonical CycloneDX-subset SBOM filename.
const SBOMFile = "sbom.cdx.json"

// Skill identifies the attested skill.
type Skill struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Entry   string `json:"entry"`
}

// Digest is a content lock over the skill's files.
type Digest struct {
	Algo  string            `json:"algo"`
	Files map[string]string `json:"files"`
}

// Filesystem capability: glob patterns the skill may read or write. Empty slices
// are omitted so the JSON never carries a null where the schema expects an array.
type Filesystem struct {
	Read  []string `json:"read,omitempty"`
	Write []string `json:"write,omitempty"`
}

// Network capability: declared outbound hosts, or the literal "none".
type Network struct {
	// Hosts holds declared hostnames. When the skill declares no network the
	// slice is empty and None is true.
	Hosts []string `json:"hosts"`
	None  bool     `json:"none"`
}

// MarshalJSON renders network as "none" (string) when no hosts are declared,
// matching the v0 schema's oneOf.
func (n Network) MarshalJSON() ([]byte, error) {
	if n.None || len(n.Hosts) == 0 {
		return json.Marshal("none")
	}
	return json.Marshal(struct {
		Hosts []string `json:"hosts"`
	}{Hosts: n.Hosts})
}

// Capabilities is the declared permission set for a skill.
type Capabilities struct {
	Filesystem Filesystem `json:"filesystem"`
	Network    Network    `json:"network"`
	Exec       []string   `json:"exec"`
	Env        []string   `json:"env"`
}

// CapabilityManifest is the top-level signable document.
type CapabilityManifest struct {
	Schema       string       `json:"schema"`
	Skill        Skill        `json:"skill"`
	Digest       Digest       `json:"digest"`
	Capabilities Capabilities `json:"capabilities"`
	SBOMRef      string       `json:"sbom_ref"`
}

// Canonical returns a deterministic JSON encoding of the manifest. Signing and
// verification both operate over this byte sequence so a re-serialized manifest
// produces an identical signature input.
func (m *CapabilityManifest) Canonical() ([]byte, error) {
	// json.Marshal sorts map keys, and we keep slices sorted at build time, so
	// the encoding is stable. Indentation is intentionally omitted to keep the
	// signed payload compact and unambiguous.
	return json.Marshal(m)
}

// Write serializes the manifest to capability-manifest.json inside dir.
func (m *CapabilityManifest) Write(dir string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ManifestFile), append(b, '\n'), 0o644)
}

// Load reads capability-manifest.json from dir.
func Load(dir string) (*CapabilityManifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, err
	}
	var m CapabilityManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", ManifestFile, err)
	}
	return &m, nil
}

// UnmarshalJSON handles the "none" | {hosts:[...]} oneOf on the network field.
func (n *Network) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == `"none"` {
		n.None = true
		n.Hosts = nil
		return nil
	}
	var obj struct {
		Hosts []string `json:"hosts"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	n.Hosts = obj.Hosts
	n.None = len(obj.Hosts) == 0
	return nil
}

// DigestDir computes a sha256 digest for every regular file under dir, skipping
// the artifacts skillsig itself emits (manifest, SBOM, signature bundle). Paths
// are stored relative to dir with forward slashes for cross-platform stability.
func DigestDir(dir string) (Digest, error) {
	d := Digest{Algo: "sha256", Files: map[string]string{}}
	err := filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if isArtifact(rel) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		d.Files[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	return d, err
}

// isArtifact reports whether rel is a file skillsig generates and therefore must
// not be folded into the content digest (it would change on every run).
func isArtifact(rel string) bool {
	switch rel {
	case ManifestFile, SBOMFile, "bundle.sig":
		return true
	}
	return false
}

// SortStrings returns a sorted, de-duplicated copy of in. Used to keep manifest
// fields deterministic.
func SortStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

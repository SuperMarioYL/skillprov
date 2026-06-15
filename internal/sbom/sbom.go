// Package sbom emits a minimal CycloneDX-subset software bill of materials for a
// skill directory. Every shipped file becomes a component with a sha256 hash so
// a consumer can independently confirm the bytes they received match what was
// signed. This is a deliberate subset of the CycloneDX 1.5 JSON spec — enough
// fields to be tool-recognizable without pulling in a full SBOM library.
package sbom

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// BOM is the top-level CycloneDX document.
type BOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

// Metadata carries the timestamp and the root component (the skill itself).
type Metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []Tool    `json:"tools"`
	Component Component `json:"component"`
}

// Tool identifies the generator.
type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Component is a single file (or the root skill) in the BOM.
type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Hashes  []Hash `json:"hashes,omitempty"`
}

// Hash is a content hash for a component.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// Build constructs a BOM from the skill's name/version and its file digests.
// fileDigests maps relative path -> hex sha256 (the same map the manifest carries).
func Build(skillName, skillVersion string, fileDigests map[string]string) *BOM {
	paths := make([]string, 0, len(fileDigests))
	for p := range fileDigests {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	comps := make([]Component, 0, len(paths))
	for _, p := range paths {
		comps = append(comps, Component{
			Type: "file",
			Name: p,
			Hashes: []Hash{
				{Alg: "SHA-256", Content: fileDigests[p]},
			},
		})
	}

	return &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + uuid4(),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{
				{Vendor: "skillprov", Name: "skillprov", Version: "0.1.0"},
			},
			Component: Component{
				Type:    "application",
				Name:    skillName,
				Version: skillVersion,
			},
		},
		Components: comps,
	}
}

// Write serializes the BOM to sbom.cdx.json in dir.
func (b *BOM) Write(dir, filename string) error {
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, filename), append(out, '\n'), 0o644)
}

// uuid4 returns a random RFC-4122 v4 UUID string. Used for the BOM serial number.
func uuid4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read failing is catastrophic; fall back to a fixed-but-valid value.
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

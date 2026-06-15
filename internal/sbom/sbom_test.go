package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Build must produce a CycloneDX-shaped document with one component per file.
func TestBuildCycloneDXSubset(t *testing.T) {
	files := map[string]string{
		"SKILL.md":         "aa",
		"scripts/run.sh":   "bb",
		"scripts/other.sh": "cc",
	}
	bom := Build("demo-skill", "1.2.3", files)

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", bom.BOMFormat)
	}
	if bom.SpecVersion != "1.5" {
		t.Errorf("specVersion = %q, want 1.5", bom.SpecVersion)
	}
	if len(bom.Components) != len(files) {
		t.Errorf("components = %d, want %d", len(bom.Components), len(files))
	}
	if bom.Metadata.Component.Name != "demo-skill" || bom.Metadata.Component.Version != "1.2.3" {
		t.Errorf("root component = %+v", bom.Metadata.Component)
	}

	// Components must be sorted by name for determinism.
	for i := 1; i < len(bom.Components); i++ {
		if bom.Components[i-1].Name > bom.Components[i].Name {
			t.Errorf("components not sorted: %q before %q",
				bom.Components[i-1].Name, bom.Components[i].Name)
		}
	}
}

// The serialized SBOM must be valid JSON and round-trip.
func TestSBOMWriteValidJSON(t *testing.T) {
	dir := t.TempDir()
	bom := Build("s", "0.1.0", map[string]string{"a": "0badc0de"})
	if err := bom.Write(dir, "sbom.cdx.json"); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "sbom.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("written SBOM is not valid JSON: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("round-tripped bomFormat = %v", doc["bomFormat"])
	}
}

package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// copyTestSkill copies a testdata skill dir into a fresh temp dir so a test can
// freely write the manifest/SBOM artifacts without mutating the source tree.
func copyTestSkill(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("..", "..", "testdata", name)
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("read testdata %s: %v", name, err)
	}
	var copyTree func(s, d string)
	copyTree = func(s, d string) {
		es, err := os.ReadDir(s)
		if err != nil {
			t.Fatalf("readdir %s: %v", s, err)
		}
		for _, e := range es {
			sp := filepath.Join(s, e.Name())
			dp := filepath.Join(d, e.Name())
			if e.IsDir() {
				if err := os.MkdirAll(dp, 0o755); err != nil {
					t.Fatal(err)
				}
				copyTree(sp, dp)
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
	_ = entries
	copyTree(src, dst)
	return dst
}

// DigestDir must hash every shipped file and skip skillsig's own artifacts.
func TestDigestDir_SkipsArtifacts(t *testing.T) {
	dir := copyTestSkill(t, "clean-skill")

	// drop artifact files that must be excluded from the digest
	for _, a := range []string{ManifestFile, SBOMFile, "bundle.sig"} {
		if err := os.WriteFile(filepath.Join(dir, a), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	d, err := DigestDir(dir)
	if err != nil {
		t.Fatalf("DigestDir: %v", err)
	}
	if d.Algo != "sha256" {
		t.Errorf("algo = %q, want sha256", d.Algo)
	}
	for _, a := range []string{ManifestFile, SBOMFile, "bundle.sig"} {
		if _, ok := d.Files[a]; ok {
			t.Errorf("artifact %q must not appear in digest", a)
		}
	}
	if _, ok := d.Files["SKILL.md"]; !ok {
		t.Errorf("digest is missing SKILL.md")
	}
	hexRe := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for p, h := range d.Files {
		if !hexRe.MatchString(h) {
			t.Errorf("digest of %s is not a 64-char lowercase hex: %q", p, h)
		}
	}
}

// Round-trip: a manifest written then re-loaded must be equal, and its canonical
// encoding must be byte-stable across calls (signing depends on this).
func TestManifestWriteLoadCanonicalStable(t *testing.T) {
	dir := copyTestSkill(t, "clean-skill")
	d, err := DigestDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := &CapabilityManifest{
		Schema:  SchemaID,
		Skill:   Skill{Name: "weather-lookup", Version: "1.0.0", Entry: "scripts/lookup.sh"},
		Digest:  d,
		SBOMRef: SBOMFile,
		Capabilities: Capabilities{
			Filesystem: Filesystem{Read: []string{"**"}},
			Network:    Network{Hosts: []string{"api.open-meteo.com"}},
			Exec:       []string{"*"},
			Env:        []string{"WEATHER_UNITS"},
		},
	}
	if err := m.Write(dir); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Skill != m.Skill {
		t.Errorf("skill roundtrip: got %+v want %+v", got.Skill, m.Skill)
	}

	c1, _ := m.Canonical()
	c2, _ := m.Canonical()
	if string(c1) != string(c2) {
		t.Errorf("canonical encoding is not stable across calls")
	}
}

// Network marshals to the string "none" when nothing is declared, and to an
// object with hosts otherwise — exactly the schema's oneOf.
func TestNetworkOneOfMarshalling(t *testing.T) {
	none, _ := json.Marshal(Network{None: true})
	if string(none) != `"none"` {
		t.Errorf("empty network = %s, want \"none\"", none)
	}

	withHosts, _ := json.Marshal(Network{Hosts: []string{"a.example", "b.example"}})
	var obj map[string]any
	if err := json.Unmarshal(withHosts, &obj); err != nil {
		t.Fatalf("network-with-hosts is not an object: %v", err)
	}
	if _, ok := obj["hosts"]; !ok {
		t.Errorf("network-with-hosts missing hosts key: %s", withHosts)
	}

	// And it round-trips back.
	var n Network
	if err := json.Unmarshal([]byte(`"none"`), &n); err != nil || !n.None {
		t.Errorf("unmarshal \"none\" -> %+v err=%v", n, err)
	}
}

// The emitted manifest must satisfy the v0 schema's structural invariants.
// We validate against the actual schema file's required-field lists rather than
// re-asserting them by hand, so the test tracks the shipped schema.
func TestEmittedManifestMatchesSchema(t *testing.T) {
	dir := copyTestSkill(t, "clean-skill")
	d, err := DigestDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := &CapabilityManifest{
		Schema:  SchemaID,
		Skill:   Skill{Name: "weather-lookup", Version: "1.0.0", Entry: "scripts/lookup.sh"},
		Digest:  d,
		SBOMRef: SBOMFile,
		Capabilities: Capabilities{
			Filesystem: Filesystem{Read: []string{"**"}},
			Network:    Network{Hosts: []string{"api.open-meteo.com"}},
			Exec:       []string{},
			Env:        []string{"WEATHER_UNITS"},
		},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	schema := loadSchema(t)
	validateObject(t, "manifest", doc, schema)

	// schema.const on "schema" field
	if doc["schema"] != SchemaID {
		t.Errorf("schema field = %v, want %q", doc["schema"], SchemaID)
	}
	// digest.algo const
	dig := doc["digest"].(map[string]any)
	if dig["algo"] != "sha256" {
		t.Errorf("digest.algo = %v, want sha256", dig["algo"])
	}
	// every digest value must match the hex pattern from the schema
	hexRe := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for p, h := range dig["files"].(map[string]any) {
		if !hexRe.MatchString(h.(string)) {
			t.Errorf("digest %s not hex64: %v", p, h)
		}
	}
}

// loadSchema reads the shipped JSON schema and returns it as a generic map.
func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "schema", "capability-manifest.v0.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	return s
}

// validateObject checks that doc contains every `required` key the schema lists
// at this level and recurses into nested object schemas. This is a focused
// subset of JSON-Schema validation — enough to assert the manifest is
// schema-shaped without pulling in a validation dependency.
func validateObject(t *testing.T, path string, doc, schema map[string]any) {
	t.Helper()
	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			key := r.(string)
			if _, present := doc[key]; !present {
				t.Errorf("%s: required field %q missing", path, key)
			}
		}
	}
	props, _ := schema["properties"].(map[string]any)
	for k, v := range doc {
		ps, ok := props[k].(map[string]any)
		if !ok {
			continue
		}
		if child, ok := v.(map[string]any); ok {
			if ps["type"] == "object" {
				validateObject(t, path+"."+k, child, ps)
			}
		}
	}
}

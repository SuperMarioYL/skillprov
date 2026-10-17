package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v0.4 m9: `skillprov version` prints the build version goreleaser stamps via
// the `-X main.version={{.Version}}` ldflag (main.go declares the `var version`
// symbol the ldflag targets, which v0.3 lacked — the stamp was a silent no-op).
// A local build passes "dev"; a release binary passes the tag.
func TestVersionCommand(t *testing.T) {
	var buf bytes.Buffer
	c := VersionCmd("v0.4.0")
	c.SetOut(&buf)
	c.SetArgs([]string{})
	if err := c.Execute(); err != nil {
		t.Fatalf("version execute: %v", err)
	}
	if got, want := buf.String(), "skillprov v0.4.0\n"; got != want {
		t.Errorf("version output = %q, want %q", got, want)
	}
}

// repoFile resolves a tracked file relative to the repo root (cmd tests run
// with cwd == cmd/, so the root is one level up).
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	return filepath.Join("..", rel)
}

// v0.8 m16: every user-visible version surface must agree with the VERSION
// file. The v0.7.0 cycle shipped with web/site.json still at 0.6.0 on the tag
// (fixed only in a post-tag commit) and docs/demo-results.json — the file the
// site renders as its demo — still at 0.6.0 on shipped main. This test asserts
// the surfaces EQUAL the VERSION file (an equality invariant, not a hardcoded
// number), so no surface can silently fall behind on a future release.
func TestVersionSurfacesInLockstep(t *testing.T) {
	raw, err := os.ReadFile(repoFile(t, "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	version := strings.TrimSpace(string(raw))
	if version == "" || version == "dev" {
		t.Fatalf("VERSION = %q, want a release version", version)
	}
	vTag := "v" + version

	// docs/demo-results.json — the site demo's recorded output — must carry the
	// current release version.
	type demoResults struct {
		Version string `json:"version"`
	}
	var demo demoResults
	b, err := os.ReadFile(repoFile(t, filepath.Join("docs", "demo-results.json")))
	if err != nil {
		t.Fatalf("read docs/demo-results.json: %v", err)
	}
	if err := json.Unmarshal(b, &demo); err != nil {
		t.Fatalf("parse docs/demo-results.json: %v", err)
	}
	if demo.Version != version {
		t.Errorf("docs/demo-results.json version = %q, want %q (the site renders this file as its demo)", demo.Version, version)
	}

	// web/site.json carries the content version twice: meta.content_version
	// ("0.8.0") and the top-level content_version ("v0.8.0").
	type siteMeta struct {
		Meta struct {
			ContentVersion string `json:"content_version"`
		} `json:"meta"`
		ContentVersion string `json:"content_version"`
	}
	var site siteMeta
	b, err = os.ReadFile(repoFile(t, filepath.Join("web", "site.json")))
	if err != nil {
		t.Fatalf("read web/site.json: %v", err)
	}
	if err := json.Unmarshal(b, &site); err != nil {
		t.Fatalf("parse web/site.json: %v", err)
	}
	if site.Meta.ContentVersion != version {
		t.Errorf("web/site.json meta.content_version = %q, want %q", site.Meta.ContentVersion, version)
	}
	if site.ContentVersion != vTag {
		t.Errorf("web/site.json content_version = %q, want %q", site.ContentVersion, vTag)
	}

	// CHANGELOG.md must have a section for the current release.
	changelog, err := os.ReadFile(repoFile(t, "CHANGELOG.md"))
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	if !strings.Contains(string(changelog), "## ["+version+"]") {
		t.Errorf("CHANGELOG.md has no \"## [%s]\" section", version)
	}

	// Both README badges must name the current release.
	for _, readme := range []string{"README.md", "README.en.md"} {
		b, err := os.ReadFile(repoFile(t, readme))
		if err != nil {
			t.Fatalf("read %s: %v", readme, err)
		}
		if !strings.Contains(string(b), vTag) {
			t.Errorf("%s does not mention %s", readme, vTag)
		}
	}
}

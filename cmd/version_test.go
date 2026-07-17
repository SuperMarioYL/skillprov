package cmd

import (
	"bytes"
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

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/SuperMarioYL/skillprov/internal/manifest"
	"github.com/SuperMarioYL/skillprov/internal/sbom"
	"github.com/SuperMarioYL/skillprov/internal/scan"
)

// ManifestCmd implements `skillprov manifest <skill-dir>`.
func ManifestCmd() *cobra.Command {
	var showObserved bool
	c := &cobra.Command{
		Use:   "manifest <skill-dir>",
		Short: "Scan a skill directory and emit a capability manifest + SBOM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			if err := assertSkillDir(dir); err != nil {
				return err
			}

			res, err := scan.Scan(dir)
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			digest, err := manifest.DigestDir(dir)
			if err != nil {
				return fmt.Errorf("digest: %w", err)
			}

			m := &manifest.CapabilityManifest{
				Schema: manifest.SchemaID,
				Skill: manifest.Skill{
					Name:    orDefault(res.SkillName, filepath.Base(absClean(dir))),
					Version: res.SkillVersion,
					Entry:   res.Entry,
				},
				Digest:       digest,
				Capabilities: res.DeclaredCapabilities(),
				SBOMRef:      manifest.SBOMFile,
			}
			if err := m.Write(dir); err != nil {
				return fmt.Errorf("write manifest: %w", err)
			}

			bom := sbom.Build(m.Skill.Name, m.Skill.Version, digest.Files)
			if err := bom.Write(dir, manifest.SBOMFile); err != nil {
				return fmt.Errorf("write sbom: %w", err)
			}

			fmt.Printf("wrote %s (%d files digested)\n",
				filepath.Join(dir, manifest.ManifestFile), len(digest.Files))
			fmt.Printf("wrote %s (CycloneDX 1.5 subset)\n",
				filepath.Join(dir, manifest.SBOMFile))

			printDeclaredVsObserved(res, showObserved)
			return nil
		},
	}
	c.Flags().BoolVar(&showObserved, "show-observed", true,
		"print the statically-observed capabilities alongside the declared set")
	return c
}

// printDeclaredVsObserved gives the author a quick read on whether their declared
// frontmatter matches what the scanner found — the moment they catch a missing
// declaration before they ship.
func printDeclaredVsObserved(res *scan.Result, show bool) {
	if !show {
		return
	}
	caps := []scan.Capability{scan.CapNet, scan.CapFSWrite, scan.CapExec, scan.CapEnv}
	fmt.Println("\ncapability   declared  observed")
	for _, c := range caps {
		fmt.Printf("  %-9s  %-7s  %s\n", c,
			yesno(res.Declared[c]),
			observedMark(res, c))
	}
}

func observedMark(res *scan.Result, c scan.Capability) string {
	n := len(res.Observed[c])
	if n == 0 {
		return "no"
	}
	ev := res.Observed[c][0]
	return fmt.Sprintf("yes (%s:%d)", ev.File, ev.Line)
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func absClean(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return filepath.Clean(dir)
	}
	return abs
}

// assertSkillDir confirms dir looks like an installable skill (has SKILL.md).
func assertSkillDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "SKILL.md")); err != nil {
		return fmt.Errorf("%s has no SKILL.md — not an installable skill", dir)
	}
	return nil
}

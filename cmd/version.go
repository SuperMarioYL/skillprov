package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// VersionCmd implements `skillprov version`. It prints the build's version
// string, which goreleaser stamps via the `-X main.version={{.Version}}` ldflag
// in .goreleaser.yaml (main.go declares the `var version` symbol that ldflag
// targets). A local `go build` prints "dev"; a release binary prints the tag.
//
// A provenance tool should be introspectable: a user (or an install pre-hook)
// can confirm which skillprov build they are about to trust before running it,
// rather than running an opaque binary. v0.3 shipped with no version string at
// all — the ldflag targeted a non-existent symbol — so this is the v0.4 fix
// (m9_version_command).
func VersionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the skillprov version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "skillprov %s\n", version)
		},
	}
}

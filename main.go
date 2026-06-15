// Command skillsig provides software-supply-chain provenance for installable
// agent skills: it builds a capability manifest + SBOM for a skill directory,
// signs it with a local ed25519 key, and verifies a downloaded skill by diffing
// the capabilities it declares against the ones a static scan actually observes.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/SuperMarioYL/skillsig/cmd"
)

func main() {
	root := &cobra.Command{
		Use:           "skillsig",
		Short:         "Provenance + capability attestation for installable agent skills",
		Long: "skillsig signs and verifies installable agent skills. It emits a capability\n" +
			"manifest (declared vs statically-observed net / fs-write / exec / env), signs it\n" +
			"with a local ed25519 key, and rejects any skill that reaches for a capability it\n" +
			"never declared.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(cmd.ManifestCmd(), cmd.SignCmd(), cmd.VerifyCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

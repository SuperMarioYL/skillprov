package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/SuperMarioYL/skillprov/internal/verify"
)

// ANSI colors. Kept tiny and local; no dependency just to colorize two words.
const (
	colReset = "\033[0m"
	colGreen = "\033[1;32m"
	colRed   = "\033[1;31m"
	colDim   = "\033[2m"
)

// VerifyCmd implements `skillprov verify <skill-dir>`. It exits non-zero (1) on
// any rejection, so it drops straight into a CI gate or an install pre-hook.
func VerifyCmd() *cobra.Command {
	var noColor bool
	c := &cobra.Command{
		Use:   "verify <skill-dir>",
		Short: "Verify a skill's signature and reject undeclared capabilities",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			if err := assertSkillDir(dir); err != nil {
				return err
			}

			v, err := verify.Run(dir)
			if err != nil {
				return err
			}

			green, red, dim, reset := colGreen, colRed, colDim, colReset
			if noColor {
				green, red, dim, reset = "", "", "", ""
			}

			fmt.Printf("verifying %s\n", dir)
			for _, line := range v.Checks {
				fmt.Printf("  %s- %s%s\n", dim, line, reset)
			}

			if v.Pass {
				fmt.Printf("\n%s PASS %s  signature valid, observed capabilities are a subset of declared\n",
					green+"\033[7m", reset)
				return nil
			}

			fmt.Printf("\n%s REJECTED %s\n", red+"\033[7m", reset)
			for _, r := range v.Reasons {
				fmt.Printf("  %s✗%s %s\n", red, reset, r)
			}
			// Non-zero exit without a duplicate cobra error dump.
			cmd.SilenceUsage = true
			return errRejected
		},
	}
	c.Flags().BoolVar(&noColor, "no-color", false, "disable colored output")
	return c
}

// errRejected signals a verification failure. main() turns any error into exit 1.
var errRejected = fmt.Errorf("verification REJECTED")

package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/SuperMarioYL/skillprov/internal/manifest"
	"github.com/SuperMarioYL/skillprov/internal/signer"
)

// SignCmd implements `skillprov sign <skill-dir> --key <keyfile>`.
func SignCmd() *cobra.Command {
	var keyPath string
	c := &cobra.Command{
		Use:   "sign <skill-dir> --key <keyfile>",
		Short: "Sign the capability manifest with a local ed25519 key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			if err := assertSkillDir(dir); err != nil {
				return err
			}

			m, err := manifest.Load(dir)
			if err != nil {
				return fmt.Errorf("load manifest: %w (run `skillprov manifest %s` first)", err, dir)
			}

			priv, err := signer.LoadOrCreateKey(keyPath)
			if err != nil {
				return fmt.Errorf("key: %w", err)
			}

			payload, err := m.Canonical()
			if err != nil {
				return fmt.Errorf("canonicalize manifest: %w", err)
			}

			bundle := signer.Sign(priv, payload)
			if err := bundle.Write(dir); err != nil {
				return fmt.Errorf("write bundle: %w", err)
			}

			fmt.Printf("signed %s\n", filepath.Join(dir, manifest.ManifestFile))
			fmt.Printf("wrote  %s (ed25519, key=%s)\n",
				filepath.Join(dir, signer.BundleFile), keyPath)
			return nil
		},
	}
	c.Flags().StringVar(&keyPath, "key", "dev.key",
		"path to the ed25519 private key (generated if it does not exist)")
	return c
}

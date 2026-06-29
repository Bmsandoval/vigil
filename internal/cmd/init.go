package cmd

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bmsandoval/vigil/internal/config"
	"github.com/bmsandoval/vigil/internal/store"
	"github.com/spf13/cobra"
)

//go:embed templates/starter.toml
var starterConfig []byte

// newInitCmd scaffolds a config.toml and initializes the SQLite store.
func newInitCmd() *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Create a starter config.toml and initialize the local store",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := config.ExpandPath(configPath)
			if err != nil {
				return err
			}
			if _, err := os.Stat(path); err == nil && !force {
				return fmt.Errorf("config already exists at %s (use --force to overwrite)", path)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return fmt.Errorf("create config dir: %w", err)
			}
			if err := os.WriteFile(path, starterConfig, 0o644); err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			cmd.Printf("wrote config: %s\n", path)

			// Load it back (resolves db_path) and create the store.
			cfg, err := config.Load(path)
			if err != nil {
				return fmt.Errorf("validate new config: %w", err)
			}
			st, err := store.Open(cfg.Settings.DBPath)
			if err != nil {
				return err
			}
			defer st.Close()
			cmd.Printf("initialized store: %s\n", st.Path())
			cmd.Println("\nNext: add a repo with 'vigil service add <name> <path>', then 'vigil refresh'.")
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "overwrite an existing config")
	return c
}

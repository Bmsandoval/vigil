package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bmsandoval/vigil/internal/config"
	"github.com/bmsandoval/vigil/internal/store"
)

// configPath is the resolved path to config.toml, set by the root persistent
// flag (default ~/.config/vigil/config.toml, or $VIGIL_CONFIG).
var configPath string

// defaultConfigPath returns the config location, honoring $VIGIL_CONFIG.
func defaultConfigPath() string {
	if v := os.Getenv("VIGIL_CONFIG"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.toml"
	}
	return filepath.Join(home, ".config", "vigil", "config.toml")
}

// loadConfig resolves and loads the active config, with a friendly hint when
// it does not exist yet.
func loadConfig() (*config.Config, error) {
	path, err := config.ExpandPath(configPath)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("no config at %s — run 'vigil init' first", path)
	}
	return config.Load(path)
}

// openStore opens the SQLite store at the config's db_path.
func openStore(cfg *config.Config) (*store.Store, error) {
	return store.Open(cfg.Settings.DBPath)
}

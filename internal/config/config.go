// Package config loads and validates Vigil's TOML configuration.
//
// The config file is the human-authored source of truth for *what* Vigil
// watches and *how* it notifies. Vigil reads it; it never rewrites it
// wholesale (the `service add` command appends blocks textually to preserve
// comments). Runtime state lives in the SQLite store, not here.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the top-level parsed configuration.
type Config struct {
	Settings  Settings   `toml:"settings"`
	Sources   Sources    `toml:"sources"`
	Services  []Service  `toml:"service"`
	Discovers []Discover `toml:"discover"`
	Notify    Notify     `toml:"notify"`
	Analysis  Analysis   `toml:"analysis"`

	// path is the file this Config was loaded from (for `service add`).
	path string
}

// Analysis configures optional deeper analysis passes.
type Analysis struct {
	// Reachability runs govulncheck on Go repos to mark findings called vs
	// imported-but-unreachable. Requires govulncheck on PATH.
	Reachability bool `toml:"reachability"`
}

// Settings holds global defaults.
type Settings struct {
	DBPath       string `toml:"db_path"`
	RefreshEvery string `toml:"refresh_every"`
	ScanEvery    string `toml:"scan_every"`
	OfflineOK    bool   `toml:"offline_ok"`
	MinSeverity  string `toml:"min_severity"`
}

// Sources configures which advisory feeds to sync.
type Sources struct {
	OSV OSVSource `toml:"osv"`
	KEV KEVSource `toml:"kev"`
	NVD NVDSource `toml:"nvd"`
}

type OSVSource struct {
	Enabled    bool     `toml:"enabled"`
	Mode       string   `toml:"mode"` // bulk | api | hybrid
	Ecosystems []string `toml:"ecosystems"`
}

type KEVSource struct {
	Enabled bool `toml:"enabled"`
}

type NVDSource struct {
	Enabled bool   `toml:"enabled"`
	APIKey  string `toml:"api_key"` // may be an "env:NAME" reference
}

// Service is a single named on-disk repository to watch.
type Service struct {
	Name        string   `toml:"name"`
	Path        string   `toml:"path"`
	Ecosystems  []string `toml:"ecosystems"`
	MinSeverity string   `toml:"min_severity"`
	Tags        []string `toml:"tags"`
	Include     []string `toml:"include"`
	Exclude     []string `toml:"exclude"`
	Notify      []string `toml:"notify"`
}

// Discover auto-enrolls repos found under a tree.
type Discover struct {
	Root               string   `toml:"root"`
	MaxDepth           int      `toml:"max_depth"`
	Exclude            []string `toml:"exclude"`
	DefaultMinSeverity string   `toml:"default_min_severity"`
}

// Notify configures output channels.
type Notify struct {
	Terminal TerminalNotify `toml:"terminal"`
	Markdown MarkdownNotify `toml:"markdown"`
	Desktop  DesktopNotify  `toml:"desktop"`
	Slack    SlackNotify    `toml:"slack"`
}

type TerminalNotify struct {
	Enabled bool `toml:"enabled"`
}

type MarkdownNotify struct {
	Enabled bool   `toml:"enabled"`
	Out     string `toml:"out"`
}

type DesktopNotify struct {
	Enabled bool     `toml:"enabled"`
	Only    []string `toml:"only"`
}

type SlackNotify struct {
	Enabled     bool     `toml:"enabled"`
	WebhookURL  string   `toml:"webhook_url"` // may be an "env:NAME" reference
	Events      []string `toml:"events"`
	MinSeverity string   `toml:"min_severity"`
}

// Path returns the file this config was loaded from.
func (c *Config) Path() string { return c.path }

// Load reads, normalizes, and validates the config at path.
func Load(path string) (*Config, error) {
	expanded, err := ExpandPath(path)
	if err != nil {
		return nil, err
	}
	var c Config
	md, err := toml.DecodeFile(expanded, &c)
	if err != nil {
		return nil, fmt.Errorf("parse config %s: %w", expanded, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		// Surface typos/unknown keys rather than silently ignoring them.
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config %s: unknown keys: %s", expanded, strings.Join(keys, ", "))
	}
	c.path = expanded
	c.applyDefaults()
	if err := c.normalize(); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Settings.DBPath == "" {
		c.Settings.DBPath = "~/.local/share/vigil/vigil.db"
	}
	if c.Settings.MinSeverity == "" {
		c.Settings.MinSeverity = "low"
	}
	if c.Settings.RefreshEvery == "" {
		c.Settings.RefreshEvery = "1h"
	}
	if c.Settings.ScanEvery == "" {
		c.Settings.ScanEvery = "6h"
	}
}

// normalize resolves env: references and expands ~ in path-like fields.
func (c *Config) normalize() error {
	var err error
	if c.Settings.DBPath, err = ExpandPath(c.Settings.DBPath); err != nil {
		return err
	}
	if c.Notify.Markdown.Out, err = ExpandPath(c.Notify.Markdown.Out); err != nil {
		return err
	}
	for i := range c.Services {
		if c.Services[i].Path, err = ExpandPath(c.Services[i].Path); err != nil {
			return err
		}
	}
	for i := range c.Discovers {
		if c.Discovers[i].Root, err = ExpandPath(c.Discovers[i].Root); err != nil {
			return err
		}
	}

	// Secrets are env: references resolved at load; an unset env var is an
	// error only when the owning source/channel is enabled (checked below).
	if c.Sources.NVD.APIKey, err = resolveEnv(c.Sources.NVD.APIKey); err != nil {
		return err
	}
	if c.Notify.Slack.WebhookURL, err = resolveEnv(c.Notify.Slack.WebhookURL); err != nil {
		return err
	}
	return nil
}

// resolveEnv turns "env:NAME" into the value of $NAME. Non-prefixed values
// pass through unchanged. A missing env var yields an empty string (callers
// validate required-ness based on whether the feature is enabled).
func resolveEnv(v string) (string, error) {
	rest, ok := strings.CutPrefix(v, "env:")
	if !ok {
		return v, nil
	}
	name := strings.TrimSpace(rest)
	if name == "" {
		return "", fmt.Errorf("malformed env reference %q", v)
	}
	return os.Getenv(name), nil
}

// ExpandPath expands a leading ~ to the user's home directory.
func ExpandPath(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve ~: %w", err)
		}
		return filepath.Join(home, strings.TrimPrefix(p, "~")), nil
	}
	return p, nil
}

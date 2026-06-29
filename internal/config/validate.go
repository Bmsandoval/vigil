package config

import (
	"fmt"
	"strings"
	"time"
)

// Severity levels, ordered low→high. Findings below a configured floor are
// suppressed from reporting.
var severityRank = map[string]int{
	"informational": 0,
	"low":           1,
	"medium":        2,
	"high":          3,
	"critical":      4,
}

// ValidSeverity reports whether s is a recognized severity label.
func ValidSeverity(s string) bool {
	_, ok := severityRank[strings.ToLower(s)]
	return ok
}

// SeverityAtLeast reports whether got meets or exceeds the floor.
func SeverityAtLeast(got, floor string) bool {
	return severityRank[strings.ToLower(got)] >= severityRank[strings.ToLower(floor)]
}

var validOSVModes = map[string]bool{"bulk": true, "api": true, "hybrid": true}

// Validate checks the config for internal consistency and required secrets.
func (c *Config) Validate() error {
	if !ValidSeverity(c.Settings.MinSeverity) {
		return fmt.Errorf("settings.min_severity %q is not a valid severity", c.Settings.MinSeverity)
	}
	if _, err := time.ParseDuration(c.Settings.RefreshEvery); err != nil {
		return fmt.Errorf("settings.refresh_every %q: %w", c.Settings.RefreshEvery, err)
	}
	if c.Settings.ScanEvery != "on-change" {
		if _, err := time.ParseDuration(c.Settings.ScanEvery); err != nil {
			return fmt.Errorf("settings.scan_every %q: must be a duration or \"on-change\"", c.Settings.ScanEvery)
		}
	}

	if c.Sources.OSV.Enabled && c.Sources.OSV.Mode != "" && !validOSVModes[c.Sources.OSV.Mode] {
		return fmt.Errorf("sources.osv.mode %q: must be bulk, api, or hybrid", c.Sources.OSV.Mode)
	}

	seen := map[string]bool{}
	for i, s := range c.Services {
		if s.Name == "" {
			return fmt.Errorf("service[%d]: name is required", i)
		}
		if seen[s.Name] {
			return fmt.Errorf("service %q: duplicate name", s.Name)
		}
		seen[s.Name] = true
		if s.Path == "" {
			return fmt.Errorf("service %q: path is required", s.Name)
		}
		if s.MinSeverity != "" && !ValidSeverity(s.MinSeverity) {
			return fmt.Errorf("service %q: min_severity %q is not valid", s.Name, s.MinSeverity)
		}
	}

	for i, d := range c.Discovers {
		if d.Root == "" {
			return fmt.Errorf("discover[%d]: root is required", i)
		}
		if d.DefaultMinSeverity != "" && !ValidSeverity(d.DefaultMinSeverity) {
			return fmt.Errorf("discover[%d]: default_min_severity %q is not valid", i, d.DefaultMinSeverity)
		}
	}

	// Required secrets: only error when the owning feature is enabled.
	if c.Notify.Slack.Enabled && c.Notify.Slack.WebhookURL == "" {
		return fmt.Errorf("notify.slack is enabled but webhook_url is empty (check the env: reference)")
	}
	return nil
}

// EffectiveMinSeverity resolves the reporting floor for a service, applying
// the cascade: service → global. (Discover defaults are applied when a repo is
// enrolled via discovery, not here.)
func (c *Config) EffectiveMinSeverity(s Service) string {
	if s.MinSeverity != "" {
		return s.MinSeverity
	}
	return c.Settings.MinSeverity
}

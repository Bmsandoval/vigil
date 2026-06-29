package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAppliesDefaultsAndCascade(t *testing.T) {
	p := writeConfig(t, `
[settings]
min_severity = "low"

[[service]]
name = "a"
path = "/tmp"
min_severity = "high"

[[service]]
name = "b"
path = "/tmp"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Settings.RefreshEvery != "1h" {
		t.Errorf("default refresh_every not applied: %q", cfg.Settings.RefreshEvery)
	}
	if got := cfg.EffectiveMinSeverity(cfg.Services[0]); got != "high" {
		t.Errorf("service override min-sev = %q, want high", got)
	}
	if got := cfg.EffectiveMinSeverity(cfg.Services[1]); got != "low" {
		t.Errorf("service inherited min-sev = %q, want low", got)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	p := writeConfig(t, `
[settings]
min_severityy = "low"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for unknown key, got nil")
	}
}

func TestValidateDuplicateServiceName(t *testing.T) {
	p := writeConfig(t, `
[[service]]
name = "dup"
path = "/tmp"
[[service]]
name = "dup"
path = "/tmp"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected duplicate-name error, got nil")
	}
}

func TestValidateBadSeverityAndDuration(t *testing.T) {
	for _, body := range []string{
		"[settings]\nmin_severity = \"urgent\"\n",
		"[settings]\nrefresh_every = \"soon\"\n",
	} {
		if _, err := Load(writeConfig(t, body)); err == nil {
			t.Errorf("expected validation error for %q", body)
		}
	}
}

func TestScanEveryOnChangeAllowed(t *testing.T) {
	p := writeConfig(t, "[settings]\nscan_every = \"on-change\"\n")
	if _, err := Load(p); err != nil {
		t.Fatalf("on-change should be valid: %v", err)
	}
}

func TestEnvResolutionAndRequiredSecret(t *testing.T) {
	t.Setenv("VIGIL_TEST_HOOK", "https://hooks.example/abc")
	p := writeConfig(t, `
[notify.slack]
enabled = true
webhook_url = "env:VIGIL_TEST_HOOK"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Notify.Slack.WebhookURL != "https://hooks.example/abc" {
		t.Errorf("env not resolved: %q", cfg.Notify.Slack.WebhookURL)
	}

	// Enabled channel with an unset secret must fail validation.
	p2 := writeConfig(t, `
[notify.slack]
enabled = true
webhook_url = "env:VIGIL_DEFINITELY_UNSET"
`)
	if _, err := Load(p2); err == nil {
		t.Fatal("expected error for missing required secret")
	}
}

func TestExpandPath(t *testing.T) {
	home, _ := os.UserHomeDir()
	got, err := ExpandPath("~/x/y")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, "x", "y"); got != want {
		t.Errorf("ExpandPath = %q, want %q", got, want)
	}
	if got, _ := ExpandPath("/abs/path"); got != "/abs/path" {
		t.Errorf("absolute path mangled: %q", got)
	}
}

func TestSeverityHelpers(t *testing.T) {
	if !SeverityAtLeast("high", "medium") {
		t.Error("high should be >= medium")
	}
	if SeverityAtLeast("low", "critical") {
		t.Error("low should not be >= critical")
	}
}

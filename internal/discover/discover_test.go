package discover

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bmsandoval/vigil/internal/config"
)

func mkGitRepo(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(path, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestResolveServicesAndDiscover(t *testing.T) {
	root := t.TempDir()
	// Two discoverable repos + one nested (should not be descended into).
	mkGitRepo(t, filepath.Join(root, "alpha"))
	mkGitRepo(t, filepath.Join(root, "beta"))
	mkGitRepo(t, filepath.Join(root, "beta", "nested")) // inside beta → skipped
	mkGitRepo(t, filepath.Join(root, "skipme"))

	// An explicit service that points at one of the discoverable repos: the
	// explicit entry must win (not be duplicated by discovery).
	cfg := &config.Config{
		Settings: config.Settings{MinSeverity: "low"},
		Services: []config.Service{
			{Name: "alpha-svc", Path: filepath.Join(root, "alpha"), MinSeverity: "high"},
		},
		Discovers: []config.Discover{
			{Root: root, MaxDepth: 2, Exclude: []string{"skipme"}, DefaultMinSeverity: "medium"},
		},
	}

	repos, err := Resolve(cfg)
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]Repo{}
	for _, r := range repos {
		byName[r.Name] = r
	}

	// alpha appears once, as the explicit service (high), not re-discovered.
	if r, ok := byName["alpha-svc"]; !ok || r.Source != "service" || r.MinSeverity != "high" {
		t.Errorf("explicit alpha service wrong/missing: %+v", r)
	}
	if _, dup := byName["alpha"]; dup {
		t.Error("alpha should not be discovered separately (already an explicit service)")
	}
	// beta discovered with the discover default severity.
	if r, ok := byName["beta"]; !ok || r.Source != "discover" || r.MinSeverity != "medium" {
		t.Errorf("beta discovery wrong/missing: %+v", r)
	}
	// nested repo inside beta is not descended into.
	if _, ok := byName["nested"]; ok {
		t.Error("nested repo inside beta should not be enrolled")
	}
	// excluded repo skipped.
	if _, ok := byName["skipme"]; ok {
		t.Error("skipme should be excluded")
	}
}

func TestResolveDepthLimit(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c", "repo")
	mkGitRepo(t, deep)

	cfg := &config.Config{
		Settings:  config.Settings{MinSeverity: "low"},
		Discovers: []config.Discover{{Root: root, MaxDepth: 2}},
	}
	repos, err := Resolve(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 0 {
		t.Errorf("repo at depth 4 should be beyond max_depth=2, got %+v", repos)
	}
}

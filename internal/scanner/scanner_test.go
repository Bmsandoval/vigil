package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bmsandoval/vigil/internal/discover"
	"github.com/bmsandoval/vigil/internal/match"
	"github.com/bmsandoval/vigil/internal/osv"
	"github.com/bmsandoval/vigil/internal/store"
)

func TestRunInventoriesAndMatches(t *testing.T) {
	dir := t.TempDir()
	repoPath := filepath.Join(dir, "app")
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatal(err)
	}
	lock := `{"lockfileVersion":3,"packages":{
		"":{"dependencies":{"lodash":"^4.17.0"}},
		"node_modules/lodash":{"version":"4.17.20"}}}`
	if err := os.WriteFile(filepath.Join(repoPath, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(filepath.Join(dir, "vigil.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	st.UpsertAdvisory(osv.Advisory{
		ID: "GHSA-lodash", Source: "ghsa", ContentHash: "h", SeverityLabel: "high",
		Affected: []osv.NormAffected{{
			Ecosystem: "npm", PackageName: "lodash", FixedVersions: []string{"4.17.21"},
			Ranges: []osv.NormRange{{Type: "SEMVER", Introduced: "0", Fixed: "4.17.21"}},
		}},
	})

	repos := []discover.Repo{{Name: "app", Path: repoPath, Source: "service", MinSeverity: "low"}}
	res, err := Run(st, repos, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Findings != 1 || res.New != 1 {
		t.Fatalf("expected 1 new finding, got %+v", res)
	}
	if len(res.Events) != 1 || res.Events[0].Type != match.EventNew {
		t.Errorf("expected 1 'new' event, got %+v", res.Events)
	}
	if res.Events[0].PackageName != "lodash" {
		t.Errorf("event package = %q", res.Events[0].PackageName)
	}
}

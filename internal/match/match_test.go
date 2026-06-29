package match

import (
	"path/filepath"
	"testing"

	"github.com/bmsandoval/vigil/internal/inventory"
	"github.com/bmsandoval/vigil/internal/osv"
	"github.com/bmsandoval/vigil/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "vigil.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// seedRepo inserts a repo with the given package instances via one manifest.
func seedRepo(t *testing.T, st *store.Store, name string, pkgs []inventory.Package) int64 {
	t.Helper()
	id, err := st.UpsertRepository(name, "/tmp/"+name, "service", "low")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveManifest(id, inventory.Manifest{
		Ecosystem: pkgs[0].Ecosystem, RelPath: "lock", Kind: inventory.KindLockfile,
		ContentHash: name + "-h", Packages: pkgs,
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func advisory(id, eco, pkg, fixed, severity string, aliases []string) osv.Advisory {
	return osv.Advisory{
		ID: id, Source: "ghsa", SeverityLabel: severity, ContentHash: id + "-h",
		Aliases: aliases,
		Affected: []osv.NormAffected{{
			Ecosystem: eco, PackageName: pkg,
			FixedVersions: []string{fixed},
			Ranges:        []osv.NormRange{{Type: "SEMVER", Introduced: "0", Fixed: fixed}},
		}},
	}
}

func TestEngineMatchesAffectedAndSkipsSafe(t *testing.T) {
	st := newStore(t)
	seedRepo(t, st, "app", []inventory.Package{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Direct: true}, // vulnerable
		{Ecosystem: "npm", Name: "express", Version: "5.0.0", Direct: true},  // safe (>= fix)
		{Ecosystem: "npm", Name: "leftpad", Version: "1.0.0", Direct: false}, // no advisory
	})
	if _, err := st.UpsertAdvisory(advisory("GHSA-lodash", "npm", "lodash", "4.17.21", "high", []string{"CVE-2021-1"})); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAdvisory(advisory("GHSA-express", "npm", "express", "4.0.0", "medium", nil)); err != nil {
		t.Fatal(err)
	}

	eng := &Engine{Store: st}
	res, err := eng.Run(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Findings != 1 || res.New != 1 {
		t.Fatalf("expected 1 new finding, got %+v", res)
	}

	views, _ := st.OpenFindings()
	if len(views) != 1 {
		t.Fatalf("expected 1 open finding, got %d", len(views))
	}
	f := views[0]
	if f.PackageName != "lodash" || f.Severity != "high" || f.Confidence != "confirmed" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.FixedVersion != "4.17.21" {
		t.Errorf("fixed version = %q, want 4.17.21", f.FixedVersion)
	}
	if f.Exploited {
		t.Error("not in KEV, should not be exploited")
	}
}

func TestEngineKEVAndDiff(t *testing.T) {
	st := newStore(t)
	seedRepo(t, st, "app", []inventory.Package{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Direct: true},
	})
	st.UpsertAdvisory(advisory("GHSA-lodash", "npm", "lodash", "4.17.21", "high", []string{"CVE-2021-1"}))
	st.UpsertExploitation("CVE-2021-1", "2024-01-01", false, "")

	eng := &Engine{Store: st}
	if _, err := eng.Run(nil); err != nil {
		t.Fatal(err)
	}
	views, _ := st.OpenFindings()
	if len(views) != 1 || !views[0].Exploited {
		t.Fatalf("expected exploited finding, got %+v", views)
	}

	// Re-scan with the package upgraded → finding should resolve.
	id, _ := st.UpsertRepository("app", "/tmp/app", "service", "low")
	st.SaveManifest(id, inventory.Manifest{
		Ecosystem: "npm", RelPath: "lock", Kind: inventory.KindLockfile, ContentHash: "app-h2",
		Packages: []inventory.Package{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Direct: true}},
	})
	res, err := eng.Run(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Resolved != 1 {
		t.Errorf("expected 1 resolved finding after upgrade, got %d", res.Resolved)
	}
	if views, _ := st.OpenFindings(); len(views) != 0 {
		t.Errorf("expected 0 open findings after upgrade, got %d", len(views))
	}
}

func TestEngineWithdrawnAdvisoryIgnored(t *testing.T) {
	st := newStore(t)
	seedRepo(t, st, "app", []inventory.Package{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Direct: true},
	})
	adv := advisory("GHSA-withdrawn", "npm", "lodash", "4.17.21", "high", nil)
	adv.Withdrawn = "2024-02-01"
	st.UpsertAdvisory(adv)

	eng := &Engine{Store: st}
	res, _ := eng.Run(nil)
	if res.Findings != 0 {
		t.Errorf("withdrawn advisory should yield no findings, got %d", res.Findings)
	}
}

func TestEngineSeverityChangeDetected(t *testing.T) {
	st := newStore(t)
	seedRepo(t, st, "app", []inventory.Package{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Direct: true},
	})
	st.UpsertAdvisory(advisory("GHSA-lodash", "npm", "lodash", "4.17.21", "medium", nil))
	eng := &Engine{Store: st}
	eng.Run(nil)

	// Advisory re-rated to critical → next scan flags a severity change.
	bumped := advisory("GHSA-lodash", "npm", "lodash", "4.17.21", "critical", nil)
	bumped.ContentHash = "changed"
	st.UpsertAdvisory(bumped)
	res, _ := eng.Run(nil)
	if res.SeverityChanges != 1 {
		t.Errorf("expected 1 severity change, got %d", res.SeverityChanges)
	}
}

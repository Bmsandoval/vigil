package match

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/bmsandoval/vigil/internal/inventory"
	"github.com/bmsandoval/vigil/internal/osv"
	"github.com/bmsandoval/vigil/internal/reachability"
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

func TestEngineDedupsCVEAliases(t *testing.T) {
	st := newStore(t)
	seedRepo(t, st, "app", []inventory.Package{
		{Ecosystem: "Go", Name: "github.com/x/y", Version: "1.0.0", Direct: true},
	})
	// Two advisories for the same package that are CVE aliases of each other:
	// a GHSA (high, with fix) and a GO- record (no severity). They must collapse
	// into a single finding, keeping the stronger (GHSA/high).
	ghsa := advisory("GHSA-aaaa", "Go", "github.com/x/y", "1.0.1", "high", []string{"CVE-2024-9999"})
	goRec := advisory("GO-2024-0001", "Go", "github.com/x/y", "", "", []string{"CVE-2024-9999"})
	st.UpsertAdvisory(ghsa)
	st.UpsertAdvisory(goRec)

	eng := &Engine{Store: st}
	res, err := eng.Run(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Findings != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", res.Findings)
	}
	views, _ := st.OpenFindings()
	if len(views) != 1 {
		t.Fatalf("expected 1 open finding, got %d", len(views))
	}
	if views[0].Severity != "high" {
		t.Errorf("merged finding should keep the stronger (high) severity, got %q", views[0].Severity)
	}
	if views[0].FixedVersion != "1.0.1" {
		t.Errorf("merged finding should carry the recorded fix 1.0.1, got %q", views[0].FixedVersion)
	}
}

func TestEngineKEVMergedAcrossAliases(t *testing.T) {
	st := newStore(t)
	seedRepo(t, st, "app", []inventory.Package{
		{Ecosystem: "Go", Name: "github.com/x/y", Version: "1.0.0", Direct: true},
	})
	// The GHSA record carries the CVE that's in KEV; the GO- record does not list
	// it. After merge, the single finding must be flagged exploited.
	st.UpsertAdvisory(advisory("GHSA-bbbb", "Go", "github.com/x/y", "1.0.1", "high", []string{"CVE-2024-8888"}))
	st.UpsertAdvisory(advisory("GO-2024-0002", "Go", "github.com/x/y", "1.0.1", "medium", []string{"CVE-2024-8888"}))
	st.UpsertExploitation("CVE-2024-8888", "2024-05-01", true, "")

	eng := &Engine{Store: st}
	if _, err := eng.Run(nil); err != nil {
		t.Fatal(err)
	}
	views, _ := st.OpenFindings()
	if len(views) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(views))
	}
	if !views[0].Exploited {
		t.Error("merged finding should be exploited (KEV via the shared CVE)")
	}
}

func TestEngineAnnotatesReachability(t *testing.T) {
	st := newStore(t)
	repoID := seedRepo(t, st, "goapp", []inventory.Package{
		{Ecosystem: "Go", Name: "github.com/reached/pkg", Version: "1.0.0", Direct: true},
		{Ecosystem: "Go", Name: "github.com/unreached/pkg", Version: "1.0.0", Direct: true},
	})
	st.UpsertAdvisory(advisory("GHSA-reached", "Go", "github.com/reached/pkg", "1.0.1", "high", []string{"CVE-2024-1"}))
	st.UpsertAdvisory(advisory("GHSA-unreached", "Go", "github.com/unreached/pkg", "1.0.1", "high", []string{"CVE-2024-2"}))

	// govulncheck report: CVE-2024-1 called, CVE-2024-2 only imported.
	rep, _ := reachability.Parse(strings.NewReader(`
{"osv":{"id":"GO-2024-1","aliases":["CVE-2024-1"]}}
{"osv":{"id":"GO-2024-2","aliases":["CVE-2024-2"]}}
{"finding":{"osv":"GO-2024-1","trace":[{"function":"Vuln","package":"github.com/reached/pkg"}]}}
{"finding":{"osv":"GO-2024-2","trace":[{"package":"github.com/unreached/pkg"}]}}
`))

	eng := &Engine{Store: st, Reachability: map[int64]*reachability.Report{repoID: rep}}
	if _, err := eng.Run(nil); err != nil {
		t.Fatal(err)
	}
	views, _ := st.OpenFindings()
	got := map[string]string{}
	for _, v := range views {
		got[v.PackageName] = v.Reachability
	}
	if got["github.com/reached/pkg"] != "called" {
		t.Errorf("reached pkg should be called, got %q", got["github.com/reached/pkg"])
	}
	if got["github.com/unreached/pkg"] != "imported" {
		t.Errorf("unreached pkg should be imported, got %q", got["github.com/unreached/pkg"])
	}
}

func TestEngineFilteredScanDoesNotResolveOtherRepos(t *testing.T) {
	st := newStore(t)
	repoA := seedRepo(t, st, "appA", []inventory.Package{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Direct: true},
	})
	repoB := seedRepo(t, st, "appB", []inventory.Package{
		{Ecosystem: "npm", Name: "express", Version: "4.0.0", Direct: true},
	})
	st.UpsertAdvisory(advisory("GHSA-lodash", "npm", "lodash", "4.17.21", "high", nil))
	st.UpsertAdvisory(advisory("GHSA-express", "npm", "express", "5.0.0", "high", nil))

	eng := &Engine{Store: st}
	if _, err := eng.Run(nil); err != nil { // full scan: both repos get a finding
		t.Fatal(err)
	}
	if v, _ := st.OpenFindings(); len(v) != 2 {
		t.Fatalf("expected 2 findings after full scan, got %d", len(v))
	}

	// Scan ONLY repoA. repoB's finding must NOT be resolved.
	res, err := eng.Run([]int64{repoA})
	if err != nil {
		t.Fatal(err)
	}
	if res.Resolved != 0 {
		t.Errorf("filtered scan of appA resolved %d findings — should be 0 (must not touch appB)", res.Resolved)
	}
	open := map[string]bool{}
	views, _ := st.OpenFindings()
	for _, v := range views {
		open[v.RepoName] = true
	}
	if !open["appA"] || !open["appB"] {
		t.Errorf("both repos should still have open findings, got %v", open)
	}
	_ = repoB
}

func TestEngineMatchSkipOnUnchangedRescan(t *testing.T) {
	st := newStore(t)
	seedRepo(t, st, "app", []inventory.Package{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Direct: true},
	})
	st.UpsertAdvisory(advisory("GHSA-lodash", "npm", "lodash", "4.17.21", "high", nil))

	eng := &Engine{Store: st}
	r1, err := eng.Run(nil)
	if err != nil {
		t.Fatal(err)
	}
	if r1.ManifestsSkipped != 0 || r1.Findings != 1 {
		t.Fatalf("first scan: skipped=%d findings=%d, want 0/1", r1.ManifestsSkipped, r1.Findings)
	}

	// Re-scan with nothing changed (no refresh, no lockfile change): the manifest
	// should be skipped, the finding preserved, nothing resolved.
	r2, err := eng.Run(nil)
	if err != nil {
		t.Fatal(err)
	}
	if r2.ManifestsSkipped != 1 {
		t.Errorf("second scan should skip 1 manifest, got %d", r2.ManifestsSkipped)
	}
	if r2.Resolved != 0 {
		t.Errorf("skip must not resolve findings, got %d resolved", r2.Resolved)
	}
	if v, _ := st.OpenFindings(); len(v) != 1 {
		t.Errorf("finding should be preserved across a skipped scan, got %d", len(v))
	}

	// After an advisory change, the skip must NOT happen (re-match).
	bumped := advisory("GHSA-lodash", "npm", "lodash", "4.17.21", "critical", nil)
	bumped.ContentHash = "v2"
	st.UpsertAdvisory(bumped)
	r3, _ := eng.Run(nil)
	if r3.ManifestsSkipped != 0 {
		t.Errorf("advisory change should invalidate skip, got %d skipped", r3.ManifestsSkipped)
	}
	if r3.SeverityChanges != 1 {
		t.Errorf("severity bump should be detected after re-match, got %d", r3.SeverityChanges)
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

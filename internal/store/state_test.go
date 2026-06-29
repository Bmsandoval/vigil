package store

import (
	"testing"

	"github.com/bmsandoval/vigil/internal/inventory"
	"github.com/bmsandoval/vigil/internal/osv"
)

// seedFinding creates a repo+instance+advisory+finding and returns its fingerprint.
func seedFinding(t *testing.T, st *Store, fingerprint string) {
	t.Helper()
	repoID, err := st.UpsertRepository("app", "/tmp/app", "service", "low")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveManifest(repoID, inventory.Manifest{
		Ecosystem: "npm", RelPath: "lock", Kind: inventory.KindLockfile, ContentHash: "h",
		Packages: []inventory.Package{{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Direct: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAdvisory(osv.Advisory{ID: "GHSA-x", Source: "ghsa", ContentHash: "ah", SeverityLabel: "high"}); err != nil {
		t.Fatal(err)
	}
	var instanceID int64
	if err := st.DB().QueryRow(`SELECT id FROM package_instances LIMIT 1`).Scan(&instanceID); err != nil {
		t.Fatal(err)
	}
	scanID, _ := st.CreateScan()
	if _, err := st.UpsertFinding(scanID, Finding{
		Fingerprint: fingerprint, RepoID: repoID, InstanceID: instanceID,
		AdvisoryID: "GHSA-x", Severity: "high", Confidence: "confirmed",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFindingStateLifecycle(t *testing.T) {
	st := newTestStore(t)
	fp := "abcdef0123456789abcdef0123456789"
	seedFinding(t, st, fp)

	// Dismiss → suppressed and visible in the view's state.
	if err := st.SetFindingState(fp, StateDismissed, "not_reachable", "false positive", "tester"); err != nil {
		t.Fatal(err)
	}
	views, _ := st.OpenFindings()
	if len(views) != 1 || views[0].State != StateDismissed || !views[0].Suppressed() {
		t.Fatalf("expected dismissed+suppressed, got %+v", views)
	}
	if n, _ := st.SuppressedCount(); n != 1 {
		t.Errorf("SuppressedCount = %d, want 1", n)
	}

	// Acknowledged is not suppressed.
	st.SetFindingState(fp, StateAcknowledged, "", "", "tester")
	views, _ = st.OpenFindings()
	if views[0].Suppressed() {
		t.Error("acknowledged should not be suppressed")
	}
	if n, _ := st.SuppressedCount(); n != 0 {
		t.Errorf("SuppressedCount after ack = %d, want 0", n)
	}

	// Reset clears state.
	if err := st.ClearFindingState(fp); err != nil {
		t.Fatal(err)
	}
	views, _ = st.OpenFindings()
	if views[0].State != "" {
		t.Errorf("state should be cleared, got %q", views[0].State)
	}
}

func TestResolveFingerprint(t *testing.T) {
	st := newTestStore(t)
	seedFinding(t, st, "aaaa1111bbbb2222")

	got, err := st.ResolveFingerprint("aaaa11")
	if err != nil || got != "aaaa1111bbbb2222" {
		t.Errorf("prefix resolve = %q err %v", got, err)
	}
	if _, err := st.ResolveFingerprint("zzzz"); err == nil {
		t.Error("expected error for no match")
	}

	// Ambiguous prefix.
	seedFindingExtra(t, st, "aaaa3333cccc4444")
	if _, err := st.ResolveFingerprint("aaaa"); err == nil {
		t.Error("expected ambiguity error")
	}
}

// seedFindingExtra adds another finding sharing the same instance/advisory.
func seedFindingExtra(t *testing.T, st *Store, fingerprint string) {
	t.Helper()
	var repoID, instanceID int64
	st.DB().QueryRow(`SELECT id FROM repositories LIMIT 1`).Scan(&repoID)
	st.DB().QueryRow(`SELECT id FROM package_instances LIMIT 1`).Scan(&instanceID)
	scanID, _ := st.CreateScan()
	if _, err := st.UpsertFinding(scanID, Finding{
		Fingerprint: fingerprint, RepoID: repoID, InstanceID: instanceID,
		AdvisoryID: "GHSA-x", Severity: "low", Confidence: "confirmed",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLookupFinding(t *testing.T) {
	st := newTestStore(t)
	fp := "deadbeefdeadbeef"
	seedFinding(t, st, fp)
	fs, err := st.LookupFinding(fp)
	if err != nil {
		t.Fatal(err)
	}
	if fs.PackageName != "lodash" || fs.AdvisoryID != "GHSA-x" {
		t.Errorf("lookup = %+v", fs)
	}
}

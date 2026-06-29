package store

import (
	"testing"

	"github.com/bmsandoval/vigil/internal/osv"
)

func sampleAdvisory(hash, severity string) osv.Advisory {
	return osv.Advisory{
		ID:            "GHSA-test",
		Source:        "ghsa",
		Summary:       "test",
		SeverityLabel: severity,
		ContentHash:   hash,
		Aliases:       []string{"CVE-2024-1111"},
		Affected: []osv.NormAffected{{
			Ecosystem:     "npm",
			PackageName:   "lodash",
			Versions:      []string{"4.17.20"},
			FixedVersions: []string{"4.17.21"},
			Ranges: []osv.NormRange{
				{Type: "SEMVER", Introduced: "0", Fixed: "4.17.21"},
			},
		}},
		References: []osv.NormReference{{Kind: "FIX", URL: "https://example/fix"}},
	}
}

func TestUpsertAdvisoryChangeDetection(t *testing.T) {
	st := newTestStore(t)

	changed, err := st.UpsertAdvisory(sampleAdvisory("h1", "high"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("first insert should be changed=true")
	}

	// Same hash → no change.
	changed, _ = st.UpsertAdvisory(sampleAdvisory("h1", "high"))
	if changed {
		t.Error("same hash should be changed=false")
	}

	// New hash + new severity → changed, and child rows replaced (not duplicated).
	changed, err = st.UpsertAdvisory(sampleAdvisory("h2", "critical"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("new hash should be changed=true")
	}

	var sev string
	if err := st.DB().QueryRow(`SELECT severity_label FROM advisories WHERE id='GHSA-test'`).Scan(&sev); err != nil {
		t.Fatal(err)
	}
	if sev != "critical" {
		t.Errorf("severity not updated: %q", sev)
	}
	// Aliases / ranges should not have duplicated on the second upsert.
	if n := countRows(st, `SELECT COUNT(*) FROM advisory_aliases WHERE advisory_id='GHSA-test'`); n != 1 {
		t.Errorf("aliases duplicated: %d", n)
	}
	if n := countRows(st, `SELECT COUNT(*) FROM advisory_ranges`); n != 1 {
		t.Errorf("ranges duplicated: %d", n)
	}
	if n := countRows(st, `SELECT COUNT(*) FROM references_links WHERE advisory_id='GHSA-test'`); n != 1 {
		t.Errorf("references duplicated: %d", n)
	}
}

func TestUpsertAdvisoriesBatch(t *testing.T) {
	st := newTestStore(t)
	batch := []osv.Advisory{
		sampleAdvisory("h1", "high"),
		{ID: "GHSA-two", Source: "ghsa", ContentHash: "x", SeverityLabel: "low",
			Affected: []osv.NormAffected{{Ecosystem: "npm", PackageName: "left-pad"}}},
	}
	changed, err := st.UpsertAdvisories(batch)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 2 {
		t.Errorf("batch: expected 2 changed, got %d", changed)
	}
	if n, _ := st.CountAdvisories(); n != 2 {
		t.Errorf("expected 2 advisories stored, got %d", n)
	}
	// Re-running the same batch → 0 changed (content-hash dedup within batch path).
	changed, _ = st.UpsertAdvisories(batch)
	if changed != 0 {
		t.Errorf("re-running identical batch should report 0 changed, got %d", changed)
	}
}

func TestMirrorRevisionBumpsOnChange(t *testing.T) {
	st := newTestStore(t)
	v0, _ := st.AdvisoryDBVersion()

	st.UpsertAdvisory(sampleAdvisory("h1", "high"))
	v1, _ := st.AdvisoryDBVersion()
	if v1 == v0 {
		t.Error("advisory insert should bump mirror revision")
	}
	// Unchanged re-upsert → no bump.
	st.UpsertAdvisory(sampleAdvisory("h1", "high"))
	v2, _ := st.AdvisoryDBVersion()
	if v2 != v1 {
		t.Errorf("unchanged advisory should not bump revision: %q -> %q", v1, v2)
	}
	// KEV insert → bump; unchanged KEV re-sync → no bump.
	st.UpsertExploitation("CVE-1", "2024-01-01", false, "")
	v3, _ := st.AdvisoryDBVersion()
	if v3 == v2 {
		t.Error("KEV insert should bump revision")
	}
	st.UpsertExploitation("CVE-1", "2024-01-01", false, "")
	v4, _ := st.AdvisoryDBVersion()
	if v4 != v3 {
		t.Errorf("unchanged KEV re-sync should not bump revision: %q -> %q", v3, v4)
	}
}

func TestUpsertExploitationAndCursor(t *testing.T) {
	st := newTestStore(t)
	if err := st.UpsertExploitation("CVE-2024-1111", "2024-03-01", true, "2024-03-21"); err != nil {
		t.Fatal(err)
	}
	var ransom int
	if err := st.DB().QueryRow(`SELECT ransomware FROM exploitation WHERE cve='CVE-2024-1111'`).Scan(&ransom); err != nil {
		t.Fatal(err)
	}
	if ransom != 1 {
		t.Error("ransomware flag not set")
	}

	if err := st.SetCursor("osv:npm", "etag-123"); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetCursor("osv:npm")
	if err != nil {
		t.Fatal(err)
	}
	if got != "etag-123" {
		t.Errorf("cursor = %q, want etag-123", got)
	}
	if missing, _ := st.GetCursor("osv:none"); missing != "" {
		t.Errorf("missing cursor should be empty, got %q", missing)
	}
}

func countRows(st *Store, query string, args ...any) int {
	var n int
	if err := st.DB().QueryRow(query, args...).Scan(&n); err != nil {
		return -1
	}
	return n
}

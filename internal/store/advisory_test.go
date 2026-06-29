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

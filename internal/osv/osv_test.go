package osv

import (
	"math"
	"testing"
)

func TestNormalizeRangesAndFixedVersions(t *testing.T) {
	raw := []byte(`{
	  "id": "GHSA-aaaa-bbbb-cccc",
	  "summary": "bad bug",
	  "aliases": ["CVE-2024-1111"],
	  "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	  "affected": [{
	    "package": {"ecosystem":"npm","name":"lodash"},
	    "ranges": [{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}],
	    "versions": ["4.17.20"]
	  }],
	  "references": [{"type":"FIX","url":"https://example/fix"}],
	  "database_specific": {"severity":"HIGH"}
	}`)
	rec, err := ParseRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	adv := rec.Normalize(raw)

	if adv.Source != "ghsa" {
		t.Errorf("source = %q, want ghsa", adv.Source)
	}
	if adv.SeverityLabel != "high" {
		t.Errorf("severity = %q, want high", adv.SeverityLabel)
	}
	if len(adv.Aliases) != 1 || adv.Aliases[0] != "CVE-2024-1111" {
		t.Errorf("aliases = %v", adv.Aliases)
	}
	if len(adv.Affected) != 1 {
		t.Fatalf("affected = %d", len(adv.Affected))
	}
	a := adv.Affected[0]
	if a.Ecosystem != "npm" || a.PackageName != "lodash" {
		t.Errorf("affected pkg = %+v", a)
	}
	if len(a.Ranges) != 1 || a.Ranges[0].Introduced != "0" || a.Ranges[0].Fixed != "4.17.21" {
		t.Errorf("ranges = %+v", a.Ranges)
	}
	if len(a.FixedVersions) != 1 || a.FixedVersions[0] != "4.17.21" {
		t.Errorf("fixed versions = %v", a.FixedVersions)
	}
	if adv.ContentHash == "" {
		t.Error("content hash should be set")
	}
}

func TestNormalizeOpenRangeAndLastAffected(t *testing.T) {
	raw := []byte(`{
	  "id": "OSV-1",
	  "affected": [{
	    "package": {"ecosystem":"Go","name":"x"},
	    "ranges": [
	      {"type":"SEMVER","events":[{"introduced":"1.0.0"}]},
	      {"type":"SEMVER","events":[{"introduced":"2.0.0"},{"last_affected":"2.5.0"}]}
	    ]
	  }]
	}`)
	rec, _ := ParseRecord(raw)
	adv := rec.Normalize(raw)
	rs := adv.Affected[0].Ranges
	if len(rs) != 2 {
		t.Fatalf("ranges = %+v", rs)
	}
	if rs[0].Introduced != "1.0.0" || rs[0].Fixed != "" || rs[0].LastAffected != "" {
		t.Errorf("open range wrong: %+v", rs[0])
	}
	if rs[1].LastAffected != "2.5.0" {
		t.Errorf("last_affected wrong: %+v", rs[1])
	}
}

func TestContentHashChangesWithBytes(t *testing.T) {
	a := []byte(`{"id":"X","modified":"2024-01-01"}`)
	b := []byte(`{"id":"X","modified":"2024-02-01"}`)
	ra, _ := ParseRecord(a)
	rb, _ := ParseRecord(b)
	if ra.Normalize(a).ContentHash == rb.Normalize(b).ContentHash {
		t.Error("different bytes should yield different content hashes")
	}
}

func TestCVSSBaseScore(t *testing.T) {
	cases := map[string]float64{
		// Known CVSS 3.1 reference vectors.
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8, // critical
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N": 3.7, // low
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1, // changed scope
	}
	for vec, want := range cases {
		if got := CVSSBaseScore(vec); math.Abs(got-want) > 0.01 {
			t.Errorf("CVSSBaseScore(%q) = %.2f, want %.2f", vec, got, want)
		}
	}
	if CVSSBaseScore("CVSS:4.0/AV:N/AC:L") != 0 {
		t.Error("v4 vector should return 0 (unsupported)")
	}
}

func TestLabelFromScore(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{{9.8, "critical"}, {7.0, "high"}, {5.0, "medium"}, {0.5, "low"}, {0, ""}}
	for _, c := range cases {
		if got := LabelFromScore(c.score); got != c.want {
			t.Errorf("LabelFromScore(%.1f) = %q, want %q", c.score, got, c.want)
		}
	}
}

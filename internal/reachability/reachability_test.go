package reachability

import (
	"strings"
	"testing"
)

// Representative govulncheck -json stream: one called vuln, one only imported.
const sample = `
{"osv":{"id":"GO-2021-0001","aliases":["CVE-2021-1111","GHSA-aaaa-bbbb-cccc"]}}
{"osv":{"id":"GO-2021-0002","aliases":["CVE-2021-2222"]}}
{"finding":{"osv":"GO-2021-0001","trace":[{"module":"example.com/bad","package":"example.com/bad","function":"Vuln"}]}}
{"finding":{"osv":"GO-2021-0002","trace":[{"module":"example.com/other","package":"example.com/other"}]}}
`

func TestParseLevelsAndAliasPropagation(t *testing.T) {
	rep, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Ran {
		t.Error("Ran should be true")
	}
	// Called vuln: looked up by GO id, CVE alias, or GHSA alias.
	if rep.Lookup("GO-2021-0001") != LevelCalled {
		t.Errorf("GO-2021-0001 should be called")
	}
	if rep.Lookup("CVE-2021-1111") != LevelCalled {
		t.Errorf("alias CVE-2021-1111 should inherit called")
	}
	if rep.Lookup("GHSA-aaaa-bbbb-cccc") != LevelCalled {
		t.Errorf("alias GHSA should inherit called")
	}
	// Imported-only vuln.
	if rep.Lookup("GO-2021-0002") != LevelImported {
		t.Errorf("GO-2021-0002 should be imported, got %v", rep.Lookup("GO-2021-0002"))
	}
	if rep.Lookup("CVE-2021-2222") != LevelImported {
		t.Errorf("alias should inherit imported")
	}
	// Unknown vuln.
	if rep.Lookup("GO-9999-9999") != LevelUnknown {
		t.Errorf("unknown vuln should be LevelUnknown")
	}
}

func TestLookupTakesMostSevere(t *testing.T) {
	rep, _ := Parse(strings.NewReader(sample))
	// Passing both a called and an imported id returns called.
	if rep.Lookup("CVE-2021-2222", "GO-2021-0001") != LevelCalled {
		t.Error("Lookup should take the most severe across ids")
	}
}

func TestParseEmptyStream(t *testing.T) {
	rep, err := Parse(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Lookup("anything") != LevelUnknown {
		t.Error("empty stream → all unknown")
	}
}

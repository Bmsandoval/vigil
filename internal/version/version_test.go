package version

import "testing"

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func TestSemverCompare(t *testing.T) {
	c, _ := For("npm")
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.4", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.0.0", "1.0.0", 0},
		{"1.0.0-alpha", "1.0.0", -1}, // prerelease < release
		{"1.0.0-alpha", "1.0.0-beta", -1},
	}
	for _, tc := range cases {
		got, err := c.Compare(tc.a, tc.b)
		if err != nil {
			t.Errorf("Compare(%q,%q) error: %v", tc.a, tc.b, err)
			continue
		}
		if sign(got) != tc.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", tc.a, tc.b, sign(got), tc.want)
		}
	}
}

func TestGoCompareNormalizesVPrefix(t *testing.T) {
	c, _ := For("Go")
	// OSV omits the leading v; go.mod includes it. Both must compare equal.
	got, err := c.Compare("v1.2.3", "1.2.3")
	if err != nil || got != 0 {
		t.Errorf("v-prefix normalization failed: got %d err %v", got, err)
	}
	if g, _ := c.Compare("v1.2.0", "v1.10.0"); sign(g) != -1 {
		t.Errorf("1.2.0 should be < 1.10.0, got %d", sign(g))
	}
}

func TestPEP440Ordering(t *testing.T) {
	c, _ := For("PyPI")
	// Canonical PEP 440 ascending order.
	ordered := []string{
		"1.0.dev1",
		"1.0a1",
		"1.0a2",
		"1.0b1",
		"1.0rc1",
		"1.0",
		"1.0.post1",
		"1.1",
		"2!1.0", // higher epoch dominates
	}
	for i := 0; i+1 < len(ordered); i++ {
		got, err := c.Compare(ordered[i], ordered[i+1])
		if err != nil {
			t.Fatalf("Compare(%q,%q): %v", ordered[i], ordered[i+1], err)
		}
		if sign(got) != -1 {
			t.Errorf("expected %q < %q, got sign %d", ordered[i], ordered[i+1], sign(got))
		}
	}
	if !c.Valid("1.2.3rc1") {
		t.Error("1.2.3rc1 should be valid")
	}
	if c.Valid("not-a-version") {
		t.Error("garbage should be invalid")
	}
}

func TestInRange(t *testing.T) {
	c, _ := For("npm")
	cases := []struct {
		v, intro, fixed, last string
		want                  bool
	}{
		{"4.17.20", "0", "4.17.21", "", true},  // affected: below fix
		{"4.17.21", "0", "4.17.21", "", false}, // at fix → safe
		{"4.17.22", "0", "4.17.21", "", false}, // above fix → safe
		{"1.5.0", "1.0.0", "2.0.0", "", true},  // within introduced..fixed
		{"0.9.0", "1.0.0", "2.0.0", "", false}, // below introduced
		{"2.5.0", "2.0.0", "", "2.5.0", true},  // last_affected inclusive
		{"2.6.0", "2.0.0", "", "2.5.0", false}, // beyond last_affected
	}
	for _, tc := range cases {
		got, err := InRange(c, tc.v, tc.intro, tc.fixed, tc.last)
		if err != nil {
			t.Errorf("InRange(%q): %v", tc.v, err)
			continue
		}
		if got != tc.want {
			t.Errorf("InRange(v=%q intro=%q fixed=%q last=%q) = %v, want %v",
				tc.v, tc.intro, tc.fixed, tc.last, got, tc.want)
		}
	}
}

func TestMinFixedAbove(t *testing.T) {
	c, _ := For("npm")
	minSafe, latest := MinFixedAbove(c, "4.17.20", []string{"4.17.21", "5.0.0", "3.0.0"})
	if minSafe != "4.17.21" {
		t.Errorf("minSafe = %q, want 4.17.21", minSafe)
	}
	if latest != "5.0.0" {
		t.Errorf("latest = %q, want 5.0.0", latest)
	}
}

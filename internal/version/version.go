// Package version provides ecosystem-aware version comparison. Correct ordering
// per ecosystem (SemVer for npm/crates.io, Go's semver for modules, PEP 440 for
// PyPI) is the foundation of low-false-positive matching: a wrong comparison
// either hides a real vulnerability or invents one.
package version

import (
	mmsemver "github.com/Masterminds/semver/v3"
	gosemver "golang.org/x/mod/semver"
)

// Comparator orders versions within one ecosystem.
type Comparator interface {
	// Compare returns -1, 0, or +1 for a<b, a==b, a>b. An error means a value
	// could not be parsed (callers degrade confidence rather than guess).
	Compare(a, b string) (int, error)
	// Valid reports whether v parses in this ecosystem.
	Valid(v string) bool
}

// For returns the comparator for an OSV ecosystem name, and whether one exists.
func For(ecosystem string) (Comparator, bool) {
	switch ecosystem {
	case "Go":
		return goComparator{}, true
	case "npm", "crates.io", "Packagist", "Pub", "Hex", "NuGet":
		return semverComparator{}, true
	case "PyPI":
		return pep440Comparator{}, true
	default:
		return nil, false
	}
}

// semverComparator implements SemVer 2.0 ordering (npm, crates.io, ...).
type semverComparator struct{}

func (semverComparator) Valid(v string) bool {
	_, err := mmsemver.NewVersion(v)
	return err == nil
}

func (semverComparator) Compare(a, b string) (int, error) {
	va, err := mmsemver.NewVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := mmsemver.NewVersion(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

// goComparator uses Go's module semver, which requires a leading "v". OSV Go
// advisories omit the "v" while go.mod includes it, so we normalize both.
type goComparator struct{}

func ensureV(v string) string {
	if v == "" {
		return v
	}
	if v[0] == 'v' {
		return v
	}
	return "v" + v
}

func (goComparator) Valid(v string) bool {
	return gosemver.IsValid(ensureV(v))
}

func (goComparator) Compare(a, b string) (int, error) {
	return gosemver.Compare(ensureV(a), ensureV(b)), nil
}

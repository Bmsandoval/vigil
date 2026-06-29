package inventory

import (
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// cargoParser reads Cargo.lock (TOML). Every [[package]] entry is a resolved
// crate with an exact version. Registry crates carry a "source"; local
// workspace members do not. Direct dependencies are cross-referenced from a
// sibling Cargo.toml when present.
type cargoParser struct{}

func (cargoParser) Ecosystem() string      { return "crates.io" }
func (cargoParser) Kind() ManifestKind     { return KindLockfile }
func (cargoParser) Match(base string) bool { return base == "Cargo.lock" }

type cargoLock struct {
	Package []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		Source  string `toml:"source"`
	} `toml:"package"`
}

func (cargoParser) Parse(absPath, relPath string) ([]Package, error) {
	var lock cargoLock
	if _, err := toml.DecodeFile(absPath, &lock); err != nil {
		return nil, err
	}
	direct := cargoDirectDeps(filepath.Join(filepath.Dir(absPath), "Cargo.toml"))

	var pkgs []Package
	for _, p := range lock.Package {
		// Skip local workspace members (no registry source): they are the
		// project itself, not dependencies to match against advisories.
		if p.Source == "" {
			continue
		}
		pkgs = append(pkgs, Package{
			Ecosystem: "crates.io",
			Name:      p.Name,
			Version:   p.Version,
			Direct:    direct[p.Name],
			Purl:      "pkg:cargo/" + p.Name + "@" + p.Version,
			Locator:   relPath,
		})
	}
	sortPackages(pkgs)
	return pkgs, nil
}

// cargoDirectDeps returns the crate names declared in a Cargo.toml's
// dependencies tables. A missing/unparseable file yields an empty set.
func cargoDirectDeps(cargoTomlPath string) map[string]bool {
	direct := map[string]bool{}
	var manifest struct {
		Dependencies      map[string]toml.Primitive `toml:"dependencies"`
		DevDependencies   map[string]toml.Primitive `toml:"dev-dependencies"`
		BuildDependencies map[string]toml.Primitive `toml:"build-dependencies"`
	}
	if _, err := toml.DecodeFile(cargoTomlPath, &manifest); err != nil {
		return direct
	}
	for _, table := range []map[string]toml.Primitive{
		manifest.Dependencies, manifest.DevDependencies, manifest.BuildDependencies,
	} {
		for name := range table {
			// A dependency may be renamed via `package = "real-name"`, but the
			// table key is the crate name in the common case.
			direct[strings.TrimSpace(name)] = true
		}
	}
	return direct
}

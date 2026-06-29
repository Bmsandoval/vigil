package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// composerParser reads composer.lock (PHP / Packagist). The "packages" and
// "packages-dev" arrays list every resolved dependency with an exact version.
// Direct dependencies are cross-referenced from composer.json's require /
// require-dev tables in the same directory.
type composerParser struct{}

func (composerParser) Ecosystem() string      { return "Packagist" }
func (composerParser) Kind() ManifestKind     { return KindLockfile }
func (composerParser) Match(base string) bool { return base == "composer.lock" }

type composerLock struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (composerParser) Parse(absPath, relPath string) ([]Package, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	direct := composerDirectDeps(filepath.Join(filepath.Dir(absPath), "composer.json"))

	var pkgs []Package
	add := func(p composerPkg) {
		if p.Name == "" || p.Version == "" {
			return
		}
		pkgs = append(pkgs, Package{
			Ecosystem: "Packagist",
			Name:      strings.ToLower(p.Name), // Packagist names are case-insensitive
			Version:   strings.TrimPrefix(p.Version, "v"),
			Direct:    direct[strings.ToLower(p.Name)],
			Purl:      "pkg:composer/" + strings.ToLower(p.Name) + "@" + p.Version,
			Locator:   relPath,
		})
	}
	for _, p := range lock.Packages {
		add(p)
	}
	for _, p := range lock.PackagesDev {
		add(p)
	}
	sortPackages(pkgs)
	return pkgs, nil
}

// composerDirectDeps returns the lowercased package names declared in a
// composer.json's require / require-dev (excluding the "php" platform and
// "ext-*" / "lib-*" virtual requirements). A missing file yields an empty set.
func composerDirectDeps(composerJSONPath string) map[string]bool {
	direct := map[string]bool{}
	var manifest struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	data, err := os.ReadFile(composerJSONPath)
	if err != nil {
		return direct
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return direct
	}
	for _, table := range []map[string]string{manifest.Require, manifest.RequireDev} {
		for name := range table {
			lname := strings.ToLower(name)
			if lname == "php" || strings.HasPrefix(lname, "ext-") || strings.HasPrefix(lname, "lib-") {
				continue // platform / virtual requirements, not packages
			}
			direct[lname] = true
		}
	}
	return direct
}

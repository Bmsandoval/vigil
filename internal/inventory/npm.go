package inventory

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
)

// npmParser reads package-lock.json. lockfileVersion 2/3 carry a flat
// "packages" map keyed by node_modules path with resolved versions; v1 carries
// a nested "dependencies" tree. Direct deps are those named in the root
// package's dependencies / devDependencies.
type npmParser struct{}

func (npmParser) Ecosystem() string      { return "npm" }
func (npmParser) Kind() ManifestKind     { return KindLockfile }
func (npmParser) Match(base string) bool { return base == "package-lock.json" }

type npmLock struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]npmPkgEntry `json:"packages"`
	Dependencies    map[string]npmDepEntry `json:"dependencies"`
}

type npmPkgEntry struct {
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type npmDepEntry struct {
	Version      string                 `json:"version"`
	Dependencies map[string]npmDepEntry `json:"dependencies"`
}

func (p npmParser) Parse(absPath, relPath string) ([]Package, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	if len(lock.Packages) > 0 {
		return p.parseV2(lock, relPath), nil
	}
	return p.parseV1(lock, relPath), nil
}

func (npmParser) parseV2(lock npmLock, relPath string) []Package {
	direct := map[string]bool{}
	if root, ok := lock.Packages[""]; ok {
		for name := range root.Dependencies {
			direct[name] = true
		}
		for name := range root.DevDependencies {
			direct[name] = true
		}
	}

	var pkgs []Package
	for key, entry := range lock.Packages {
		if key == "" || entry.Version == "" {
			continue
		}
		name := npmNameFromKey(key)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, Package{
			Ecosystem: "npm",
			Name:      name,
			Version:   entry.Version,
			Direct:    direct[name],
			Purl:      "pkg:npm/" + name + "@" + entry.Version,
			Locator:   relPath,
		})
	}
	sortPackages(pkgs)
	return pkgs
}

func (npmParser) parseV1(lock npmLock, relPath string) []Package {
	var pkgs []Package
	var walk func(deps map[string]npmDepEntry, depth int)
	walk = func(deps map[string]npmDepEntry, depth int) {
		for name, entry := range deps {
			if entry.Version != "" {
				pkgs = append(pkgs, Package{
					Ecosystem: "npm",
					Name:      name,
					Version:   entry.Version,
					Direct:    depth == 0,
					Purl:      "pkg:npm/" + name + "@" + entry.Version,
					Locator:   relPath,
				})
			}
			walk(entry.Dependencies, depth+1)
		}
	}
	walk(lock.Dependencies, 0)
	sortPackages(pkgs)
	return pkgs
}

// npmNameFromKey extracts the package name from a packages-map key such as
// "node_modules/foo", "node_modules/@scope/pkg", or a nested
// "node_modules/a/node_modules/b".
func npmNameFromKey(key string) string {
	const marker = "node_modules/"
	idx := strings.LastIndex(key, marker)
	if idx < 0 {
		return ""
	}
	return key[idx+len(marker):]
}

func sortPackages(pkgs []Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
}

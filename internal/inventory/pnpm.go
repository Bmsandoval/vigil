package inventory

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// pnpmParser reads pnpm-lock.yaml. The "packages" map holds every resolved
// dependency keyed by "name@version" (v9) or "/name@version" (v6), optionally
// with a peer-suffix like "(react@18.0.0)". Direct deps come from the
// importers section (v9) or the top-level dependencies maps (v6).
type pnpmParser struct{}

func (pnpmParser) Ecosystem() string      { return "npm" }
func (pnpmParser) Kind() ManifestKind     { return KindLockfile }
func (pnpmParser) Match(base string) bool { return base == "pnpm-lock.yaml" }

type pnpmLock struct {
	Importers       map[string]pnpmImporter `yaml:"importers"`
	Dependencies    map[string]pnpmDep      `yaml:"dependencies"`
	DevDependencies map[string]pnpmDep      `yaml:"devDependencies"`
	Packages        map[string]any          `yaml:"packages"`
}

type pnpmImporter struct {
	Dependencies    map[string]pnpmDep `yaml:"dependencies"`
	DevDependencies map[string]pnpmDep `yaml:"devDependencies"`
}

type pnpmDep struct {
	Version string `yaml:"version"`
}

func (pnpmParser) Parse(absPath, relPath string) ([]Package, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	var lock pnpmLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	direct := map[string]bool{}
	addDirect := func(m map[string]pnpmDep) {
		for name := range m {
			direct[name] = true
		}
	}
	for _, imp := range lock.Importers {
		addDirect(imp.Dependencies)
		addDirect(imp.DevDependencies)
	}
	addDirect(lock.Dependencies)
	addDirect(lock.DevDependencies)

	var pkgs []Package
	for key := range lock.Packages {
		name, version := pnpmSplitKey(key)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, Package{
			Ecosystem: "npm",
			Name:      name,
			Version:   version,
			Direct:    direct[name],
			Purl:      "pkg:npm/" + name + "@" + version,
			Locator:   relPath,
		})
	}
	sortPackages(pkgs)
	return pkgs, nil
}

// pnpmSplitKey turns a packages-map key into (name, version), stripping a
// leading slash and any "(peer@x)" suffix.
func pnpmSplitKey(key string) (string, string) {
	key = strings.TrimPrefix(key, "/")
	if i := strings.IndexByte(key, '('); i >= 0 {
		key = key[:i]
	}
	at := strings.LastIndexByte(key, '@')
	if at <= 0 { // <=0 also rejects a leading '@' (scope with no version)
		return "", ""
	}
	return key[:at], key[at+1:]
}

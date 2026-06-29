package inventory

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// requirementsParser reads pinned requirements.txt entries ("name==version").
// Unpinned lines are skipped — without a resolved version they cannot be
// matched precisely, and would only produce low-confidence noise.
type requirementsParser struct{}

func (requirementsParser) Ecosystem() string  { return "PyPI" }
func (requirementsParser) Kind() ManifestKind { return KindManifest }
func (requirementsParser) Match(base string) bool {
	return base == "requirements.txt"
}

func (requirementsParser) Parse(absPath, relPath string) ([]Package, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 { // strip trailing comment
			line = strings.TrimSpace(line[:i])
		}
		// Drop environment markers ("; python_version < '3.9'").
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		name, version, ok := strings.Cut(line, "==")
		if !ok {
			continue // only pinned deps are inventoried
		}
		// Strip extras: "requests[security]".
		if i := strings.IndexByte(name, '['); i >= 0 {
			name = name[:i]
		}
		name = normalizePyPI(name)
		version = strings.TrimSpace(version)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, Package{
			Ecosystem: "PyPI",
			Name:      name,
			Version:   version,
			Direct:    true, // requirements.txt lists deps the project asks for
			Purl:      "pkg:pypi/" + name + "@" + version,
			Locator:   fmt.Sprintf("%s:%d", relPath, lineNo),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sortPackages(pkgs)
	return pkgs, nil
}

// poetryParser reads poetry.lock (TOML). The lock lists every resolved package
// (direct + transitive) but does not itself record which are direct, so we
// cross-reference pyproject.toml in the same directory when present.
type poetryParser struct{}

func (poetryParser) Ecosystem() string      { return "PyPI" }
func (poetryParser) Kind() ManifestKind     { return KindLockfile }
func (poetryParser) Match(base string) bool { return base == "poetry.lock" }

type poetryLock struct {
	Package []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
	} `toml:"package"`
}

func (poetryParser) Parse(absPath, relPath string) ([]Package, error) {
	var lock poetryLock
	if _, err := toml.DecodeFile(absPath, &lock); err != nil {
		return nil, err
	}
	direct := poetryDirectDeps(filepath.Join(filepath.Dir(absPath), "pyproject.toml"))

	pkgs := make([]Package, 0, len(lock.Package))
	for _, p := range lock.Package {
		name := normalizePyPI(p.Name)
		pkgs = append(pkgs, Package{
			Ecosystem: "PyPI",
			Name:      name,
			Version:   p.Version,
			Direct:    direct[name],
			Purl:      "pkg:pypi/" + name + "@" + p.Version,
			Locator:   relPath,
		})
	}
	sortPackages(pkgs)
	return pkgs, nil
}

// poetryDirectDeps returns the normalized names of dependencies declared in
// pyproject.toml ([tool.poetry.dependencies] and PEP 621 [project] deps). A
// missing or unparseable file yields an empty set (all marked transitive).
func poetryDirectDeps(pyprojectPath string) map[string]bool {
	direct := map[string]bool{}
	var pp struct {
		Tool struct {
			Poetry struct {
				Dependencies      map[string]any `toml:"dependencies"`
				DevDependencies   map[string]any `toml:"dev-dependencies"`
				GroupDependencies map[string]struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if _, err := toml.DecodeFile(pyprojectPath, &pp); err != nil {
		return direct
	}
	for name := range pp.Tool.Poetry.Dependencies {
		if strings.EqualFold(name, "python") {
			continue
		}
		direct[normalizePyPI(name)] = true
	}
	for name := range pp.Tool.Poetry.DevDependencies {
		direct[normalizePyPI(name)] = true
	}
	for _, g := range pp.Tool.Poetry.GroupDependencies {
		for name := range g.Dependencies {
			direct[normalizePyPI(name)] = true
		}
	}
	return direct
}

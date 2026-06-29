package inventory

import (
	"fmt"
	"os"

	"golang.org/x/mod/modfile"
)

// goParser reads go.mod. The require directives give every module and its
// resolved version; the `// indirect` marker distinguishes transitive deps.
// go.sum carries only hashes, so go.mod is the inventory source of truth.
type goParser struct{}

func (goParser) Ecosystem() string      { return "Go" }
func (goParser) Kind() ManifestKind     { return KindLockfile }
func (goParser) Match(base string) bool { return base == "go.mod" }

func (goParser) Parse(absPath, relPath string) ([]Package, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	f, err := modfile.Parse(absPath, data, nil)
	if err != nil {
		return nil, err
	}
	pkgs := make([]Package, 0, len(f.Require))
	for _, r := range f.Require {
		line := 0
		if r.Syntax != nil {
			line = r.Syntax.Start.Line
		}
		pkgs = append(pkgs, Package{
			Ecosystem: "Go",
			Name:      r.Mod.Path,
			Version:   r.Mod.Version,
			Direct:    !r.Indirect,
			Purl:      "pkg:golang/" + r.Mod.Path + "@" + r.Mod.Version,
			Locator:   fmt.Sprintf("%s:%d", relPath, line),
		})
	}
	return pkgs, nil
}

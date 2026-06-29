// Package inventory discovers dependency manifests in a repository and parses
// them into resolved package instances.
//
// The design favors lockfiles (the package manager's fully-resolved,
// transitively-pinned answer) over manifests (version ranges). Each parser
// reports an OSV ecosystem name so downstream matching can join against the
// advisory mirror by (ecosystem, name).
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Package is a single resolved dependency present in a repository.
type Package struct {
	Ecosystem string // OSV ecosystem: "Go", "npm", "PyPI", ...
	Name      string
	Version   string
	Direct    bool   // declared directly vs pulled in transitively
	Purl      string // package URL, e.g. pkg:golang/foo@v1.2.3
	Locator   string // "file:line" of the declaration, relative to repo
}

// ManifestKind distinguishes precise lockfiles from looser manifests.
type ManifestKind string

const (
	KindLockfile ManifestKind = "lockfile"
	KindManifest ManifestKind = "manifest"
)

// Manifest is one parsed dependency file within a repository.
type Manifest struct {
	Ecosystem   string
	RelPath     string // path relative to the repo root
	Kind        ManifestKind
	ContentHash string // sha256 of the file bytes
	Packages    []Package
}

// Parser handles one or more dependency file formats for an ecosystem.
type Parser interface {
	// Ecosystem returns the OSV ecosystem name this parser produces.
	Ecosystem() string
	// Kind reports whether this parser yields a precise lockfile or a manifest.
	Kind() ManifestKind
	// Match reports whether the given base filename is handled by this parser.
	Match(base string) bool
	// Parse reads the file at absPath and returns its packages. relPath is the
	// repo-relative path, used to build per-package locators.
	Parse(absPath, relPath string) ([]Package, error)
}

// registry is the ordered set of known parsers. Lockfile parsers come first so
// that when both a lockfile and a manifest exist for an ecosystem, the precise
// one is detected.
var registry = []Parser{
	goParser{},
	npmParser{},
	pnpmParser{},
	poetryParser{},
	requirementsParser{},
	cargoParser{},
	composerParser{},
}

// Scan walks repoRoot, parses every recognized dependency file, and returns the
// manifests found. ecosystems, when non-empty, restricts results to those OSV
// ecosystem names. excludes are glob patterns (matched against repo-relative
// paths) to skip.
func Scan(repoRoot string, ecosystems, excludes []string) ([]Manifest, error) {
	allow := toSet(ecosystems)
	var manifests []Manifest

	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting the scan
		}
		rel, _ := filepath.Rel(repoRoot, path)
		if d.IsDir() {
			if shouldSkipDir(rel, d.Name(), excludes) {
				return fs.SkipDir
			}
			return nil
		}
		base := d.Name()
		for _, p := range registry {
			if !p.Match(base) {
				continue
			}
			if len(allow) > 0 && !allow[p.Ecosystem()] {
				continue
			}
			if matchesAny(rel, excludes) {
				continue
			}
			hash, herr := hashFile(path)
			if herr != nil {
				return nil
			}
			pkgs, perr := p.Parse(path, rel)
			if perr != nil {
				return fmt.Errorf("parse %s: %w", rel, perr)
			}
			manifests = append(manifests, Manifest{
				Ecosystem:   p.Ecosystem(),
				RelPath:     rel,
				Kind:        p.Kind(),
				ContentHash: hash,
				Packages:    pkgs,
			})
			break // one parser per file
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return manifests, nil
}

// defaultSkipDirs are never worth descending into for dependency discovery.
var defaultSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	".venv": true, "venv": true, "__pycache__": true,
	"testdata": true, ".terraform": true, "dist": true, "build": true,
	"target": true, // Rust/Java build output
}

func shouldSkipDir(rel, name string, excludes []string) bool {
	if rel == "." {
		return false
	}
	if defaultSkipDirs[name] {
		return true
	}
	return matchesAny(rel, excludes)
}

func matchesAny(rel string, patterns []string) bool {
	rel = filepath.ToSlash(rel)
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, rel); ok {
			return true
		}
		// Support "**/x" style by also matching on the base name and any segment.
		trimmed := strings.TrimPrefix(pat, "**/")
		if ok, _ := filepath.Match(trimmed, filepath.Base(rel)); ok {
			return true
		}
	}
	return false
}

func toSet(xs []string) map[string]bool {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// normalizePyPI applies PEP 503 normalization to a Python package name.
func normalizePyPI(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	prevDash := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteRune(r)
		prevDash = false
	}
	return strings.Trim(b.String(), "-")
}

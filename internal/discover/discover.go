// Package discover resolves the configured services and discover-roots into a
// concrete list of repositories to inventory.
package discover

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmsandoval/vigil/internal/config"
)

// Repo is a resolved repository to scan.
type Repo struct {
	Name        string
	Path        string   // absolute
	Source      string   // "service" | "discover"
	MinSeverity string   // effective reporting floor
	Ecosystems  []string // restrict, or empty for auto
	Excludes    []string
}

// Resolve expands explicit services and any discover roots into a deduplicated
// repo list. Explicit services win over discovered ones at the same path.
func Resolve(cfg *config.Config) ([]Repo, error) {
	var repos []Repo
	seen := map[string]bool{}

	for _, s := range cfg.Services {
		abs, err := filepath.Abs(s.Path)
		if err != nil {
			abs = s.Path
		}
		seen[abs] = true
		repos = append(repos, Repo{
			Name:        s.Name,
			Path:        abs,
			Source:      "service",
			MinSeverity: cfg.EffectiveMinSeverity(s),
			Ecosystems:  s.Ecosystems,
			Excludes:    s.Exclude,
		})
	}

	for _, d := range cfg.Discovers {
		found, err := discoverRepos(d.Root, d.MaxDepth, d.Exclude)
		if err != nil {
			return nil, err
		}
		for _, path := range found {
			if seen[path] {
				continue
			}
			seen[path] = true
			minSev := d.DefaultMinSeverity
			if minSev == "" {
				minSev = cfg.Settings.MinSeverity
			}
			repos = append(repos, Repo{
				Name:        filepath.Base(path),
				Path:        path,
				Source:      "discover",
				MinSeverity: minSev,
				Excludes:    d.Exclude,
			})
		}
	}
	return repos, nil
}

// discoverRepos walks root up to maxDepth levels deep and returns directories
// that contain a .git entry. maxDepth <= 0 means unlimited.
func discoverRepos(root string, maxDepth int, excludes []string) ([]string, error) {
	root = filepath.Clean(root)
	var repos []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		depth := 0
		if rel != "." {
			depth = strings.Count(rel, string(filepath.Separator)) + 1
		}
		if maxDepth > 0 && depth > maxDepth {
			return fs.SkipDir
		}
		if matchesAny(rel, excludes) {
			return fs.SkipDir
		}
		if isGitRepo(path) {
			repos = append(repos, path)
			return fs.SkipDir // don't descend into nested repos
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return repos, nil
}

func isGitRepo(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil && (info.IsDir() || info.Mode().IsRegular())
}

func matchesAny(rel string, patterns []string) bool {
	rel = filepath.ToSlash(rel)
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, rel); ok {
			return true
		}
		trimmed := strings.TrimPrefix(pat, "**/")
		if ok, _ := filepath.Match(trimmed, filepath.Base(rel)); ok {
			return true
		}
	}
	return false
}

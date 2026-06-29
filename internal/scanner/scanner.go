// Package scanner runs the inventory→match pipeline over a set of repositories.
// It is the shared core behind the `scan` command, the `watch` daemon, and any
// future desktop UI — all of them call Run rather than re-implementing the flow.
package scanner

import (
	"context"
	"fmt"

	"github.com/bmsandoval/vigil/internal/discover"
	"github.com/bmsandoval/vigil/internal/inventory"
	"github.com/bmsandoval/vigil/internal/match"
	"github.com/bmsandoval/vigil/internal/reachability"
	"github.com/bmsandoval/vigil/internal/store"
)

// Options tunes a scan run.
type Options struct {
	// Reachability enables govulncheck analysis for Go repos.
	Reachability bool
	// Runner overrides the govulncheck runner (for tests); nil uses the real one.
	Runner reachability.Runner
	// OnReachError, if set, is called when reachability analysis fails for a repo.
	OnReachError func(repo string, err error)
}

// Run inventories each repo, persists it, then matches against the advisory
// mirror. Per-repo inventory errors are reported via onRepoError (may be nil)
// and do not abort the run. It returns the match result (including events).
func Run(st *store.Store, repos []discover.Repo, onRepoError func(repo string, err error), opts Options) (match.Result, error) {
	var repoIDs []int64
	goRepos := map[int64]string{} // repo id → path, for reachability
	for _, repo := range repos {
		manifests, err := inventory.Scan(repo.Path, repo.Ecosystems, repo.Excludes)
		if err != nil {
			if onRepoError != nil {
				onRepoError(repo.Name, err)
			}
			continue
		}
		repoID, err := st.UpsertRepository(repo.Name, repo.Path, repo.Source, repo.MinSeverity)
		if err != nil {
			return match.Result{}, err
		}
		for _, m := range manifests {
			if _, err := st.SaveManifest(repoID, m); err != nil {
				return match.Result{}, fmt.Errorf("save manifest %s: %w", m.RelPath, err)
			}
			if m.Ecosystem == "Go" {
				goRepos[repoID] = repo.Path
			}
		}
		repoIDs = append(repoIDs, repoID)
	}

	eng := &match.Engine{Store: st}

	if opts.Reachability && len(goRepos) > 0 {
		runner := opts.Runner
		if runner == nil {
			runner = reachability.ExecRunner
		}
		reports := map[int64]*reachability.Report{}
		for id, path := range goRepos {
			rep, err := reachability.Analyze(context.Background(), path, runner)
			if err != nil {
				if opts.OnReachError != nil {
					opts.OnReachError(path, err)
				}
				continue
			}
			reports[id] = rep
		}
		eng.Reachability = reports
	}

	return eng.Run(repoIDs)
}

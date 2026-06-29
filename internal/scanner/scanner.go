// Package scanner runs the inventory→match pipeline over a set of repositories.
// It is the shared core behind the `scan` command, the `watch` daemon, and any
// future desktop UI — all of them call Run rather than re-implementing the flow.
package scanner

import (
	"fmt"

	"github.com/bmsandoval/vigil/internal/discover"
	"github.com/bmsandoval/vigil/internal/inventory"
	"github.com/bmsandoval/vigil/internal/match"
	"github.com/bmsandoval/vigil/internal/store"
)

// Run inventories each repo, persists it, then matches against the advisory
// mirror. Per-repo inventory errors are reported via onRepoError (may be nil)
// and do not abort the run. It returns the match result (including events).
func Run(st *store.Store, repos []discover.Repo, onRepoError func(repo string, err error)) (match.Result, error) {
	var repoIDs []int64
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
		}
		repoIDs = append(repoIDs, repoID)
	}

	eng := &match.Engine{Store: st}
	return eng.Run(repoIDs)
}

package cmd

import (
	"fmt"

	"github.com/bmsandoval/vigil/internal/config"
	"github.com/bmsandoval/vigil/internal/ingest"
	"github.com/bmsandoval/vigil/internal/store"
	"github.com/spf13/cobra"
)

// newRefreshCmd syncs the local advisory mirror. This is the only command that
// touches the network.
func newRefreshCmd() *cobra.Command {
	var only []string
	c := &cobra.Command{
		Use:   "refresh",
		Short: "Sync the local advisory mirror (OSV, KEV) — the only networked command",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			ecosystems, err := resolveEcosystems(st, cfg.Sources.OSV.Ecosystems)
			if err != nil {
				return err
			}
			performRefresh(cmd, st, cfg, ecosystems, only)
			advTotal, _ := st.CountAdvisories()
			cmd.Printf("mirror now holds %d advisories.\n", advTotal)
			return nil
		},
	}
	c.Flags().StringSliceVar(&only, "source", nil, "limit to specific sources (osv,kev); omit for all enabled")
	return c
}

// performRefresh runs the OSV/KEV sync and prints a summary. Shared by the
// refresh command and the watch daemon.
func performRefresh(cmd *cobra.Command, st *store.Store, cfg *config.Config, ecosystems, only []string) {
	doOSV := cfg.Sources.OSV.Enabled && wants(only, "osv")
	doKEV := cfg.Sources.KEV.Enabled && wants(only, "kev")

	if doOSV && len(ecosystems) == 0 {
		cmd.Println("no ecosystems to sync — run 'vigil scan' first, or set sources.osv.ecosystems.")
	}

	r := &ingest.Refresher{Store: st, Log: func(m string) { cmd.Println(m) }}
	var osvEcos []string
	if doOSV {
		osvEcos = ecosystems
	}
	res := r.Refresh(osvEcos, doKEV)

	var total, changed int
	for _, er := range res.OSV {
		if er.Err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "  osv %s: %v\n", er.Ecosystem, er.Err)
			continue
		}
		if er.NotModified {
			cmd.Printf("  osv %s: up to date\n", er.Ecosystem)
			continue
		}
		total += er.Total
		changed += er.Changed
	}
	if doOSV {
		cmd.Printf("OSV: %d advisories synced, %d new/changed.\n", total, changed)
	}
	if doKEV {
		if res.KEVErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "  kev: %v\n", res.KEVErr)
		} else {
			cmd.Printf("KEV: %d exploited CVEs.\n", res.KEVCount)
		}
	}
}

// resolveEcosystems returns the OSV ecosystems to sync: the configured list, or
// (when "auto" / empty) the ecosystems present in the current inventory.
func resolveEcosystems(st ecosystemLister, configured []string) ([]string, error) {
	explicit := make([]string, 0, len(configured))
	auto := len(configured) == 0
	for _, e := range configured {
		if e == "auto" {
			auto = true
			continue
		}
		explicit = append(explicit, e)
	}
	if len(explicit) > 0 {
		return explicit, nil
	}
	if auto {
		return st.DistinctEcosystems()
	}
	return nil, nil
}

type ecosystemLister interface {
	DistinctEcosystems() ([]string, error)
}

// wants reports whether source s should run given an optional --source filter.
func wants(only []string, s string) bool {
	if len(only) == 0 {
		return true
	}
	for _, o := range only {
		if o == s {
			return true
		}
	}
	return false
}

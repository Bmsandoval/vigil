package cmd

import (
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/bmsandoval/vigil/internal/config"
	"github.com/bmsandoval/vigil/internal/store"
	"github.com/spf13/cobra"
)

// shortID is the displayed finding identifier — a prefix of the fingerprint,
// long enough to be unique in practice and short enough to type.
func shortID(fingerprint string) string {
	if len(fingerprint) > 10 {
		return fingerprint[:10]
	}
	return fingerprint
}

// newFindingsCmd lists open findings with their ids for ack/dismiss.
func newFindingsCmd() *cobra.Command {
	var (
		minSev  string
		showAll bool
	)
	c := &cobra.Command{
		Use:   "findings",
		Short: "List open findings (use the ID with ack/dismiss)",
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

			rows, err := st.OpenFindings()
			if err != nil {
				return err
			}
			var shown []store.FindingView
			for _, r := range rows {
				if r.Suppressed() && !showAll {
					continue
				}
				if minSev != "" && !config.SeverityAtLeast(r.Severity, minSev) {
					continue
				}
				shown = append(shown, r)
			}
			if len(shown) == 0 {
				cmd.Println("no findings to show.")
				return nil
			}
			sort.Slice(shown, func(i, j int) bool { return findingLess(shown[i], shown[j]) })

			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSEVERITY\tKEV\tREPO\tPACKAGE\tVERSION\tFIX\tADVISORY\tSTATE")
			for _, r := range shown {
				kev := ""
				if r.Exploited {
					kev = "⚠"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					shortID(r.Fingerprint), r.Severity, kev, r.RepoName, r.PackageName,
					r.Version, orDash(r.FixedVersion), r.AdvisoryID, orDash(r.State))
			}
			tw.Flush()
			return nil
		},
	}
	c.Flags().StringVar(&minSev, "min-severity", "", "only show findings at or above this severity")
	c.Flags().BoolVar(&showAll, "all", false, "include dismissed / won't-fix findings")
	return c
}

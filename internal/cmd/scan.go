package cmd

import (
	"fmt"
	"path/filepath"
	"sort"
	"text/tabwriter"

	"github.com/bmsandoval/vigil/internal/config"
	"github.com/bmsandoval/vigil/internal/discover"
	"github.com/bmsandoval/vigil/internal/match"
	"github.com/bmsandoval/vigil/internal/scanner"
	"github.com/bmsandoval/vigil/internal/store"
	"github.com/spf13/cobra"
)

// newScanCmd inventories watched repos and matches them against the advisory
// mirror, reporting findings.
func newScanCmd() *cobra.Command {
	var (
		service string
		tag     string
		minSev  string
	)
	c := &cobra.Command{
		Use:   "scan",
		Short: "Inventory watched repos and report findings (offline)",
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

			repos, err := discover.Resolve(cfg)
			if err != nil {
				return err
			}
			repos = filterRepos(repos, cfg, service, tag)
			if len(repos) == 0 {
				cmd.Println("no repositories to scan (check your config or --service/--tag filters)")
				return nil
			}

			// 1. Guard: need advisories to match against.
			if n, _ := st.CountAdvisories(); n == 0 {
				cmd.Println("advisory mirror is empty — run 'vigil refresh' first to fetch advisories.")
				return nil
			}

			// 2. Inventory + match (shared pipeline).
			res, err := scanner.Run(st, repos, func(repo string, e error) {
				fmt.Fprintf(cmd.ErrOrStderr(), "  %s: %v\n", repo, e)
			})
			if err != nil {
				return err
			}

			// 3. Report to terminal.
			if err := reportFindings(cmd, st, res, minSev); err != nil {
				return err
			}

			// 4. Dispatch notifications to non-terminal channels (desktop/webhook).
			disp := buildDispatcher(cfg, st, cmd.OutOrStdout(), false)
			if len(disp.Channels) > 0 {
				dr := disp.Dispatch(res.Events)
				if dr.Sent > 0 {
					cmd.Printf("sent %d notification(s).\n", dr.Sent)
				}
				for _, e := range dr.Errors {
					fmt.Fprintf(cmd.ErrOrStderr(), "  notify: %v\n", e)
				}
			}

			// 5. Auto-write the markdown report when configured.
			if cfg.Notify.Markdown.Enabled && cfg.Notify.Markdown.Out != "" {
				path := filepath.Join(cfg.Notify.Markdown.Out, "vigil-report.md")
				if err := writeReportFile(st, path); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "  (markdown report: %v)\n", err)
				} else {
					cmd.Printf("markdown report: %s\n", path)
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&service, "service", "", "scan a single named service")
	c.Flags().StringVar(&tag, "tag", "", "scan all services with this tag")
	c.Flags().StringVar(&minSev, "min-severity", "", "only show findings at or above this severity")
	return c
}

func reportFindings(cmd *cobra.Command, st *store.Store, res match.Result, minSev string) error {
	all, err := st.OpenFindings()
	if err != nil {
		return err
	}
	var rows []store.FindingView
	suppressed := 0
	for _, r := range all {
		if r.Suppressed() {
			suppressed++
			continue
		}
		rows = append(rows, r)
	}
	if minSev != "" {
		rows = filterBySeverity(rows, minSev)
	}
	if len(rows) == 0 {
		cmd.Printf("\nscanned %d repo(s) — no open findings", res.RepoCount)
		if res.Resolved > 0 {
			cmd.Printf(" (%d resolved since last scan)", res.Resolved)
		}
		if suppressed > 0 {
			cmd.Printf(" (%d dismissed)", suppressed)
		}
		cmd.Println(".")
		return nil
	}

	sort.Slice(rows, func(i, j int) bool { return findingLess(rows[i], rows[j]) })

	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tKEV\tREPO\tPACKAGE\tVERSION\tFIX\tADVISORY\tCONF")
	for _, r := range rows {
		kev := ""
		if r.Exploited {
			kev = "⚠"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Severity, kev, r.RepoName, r.PackageName, r.Version,
			orDash(r.FixedVersion), r.AdvisoryID, r.Confidence)
	}
	tw.Flush()

	cmd.Printf("\n%d open finding(s) across %d repo(s): %d new, %d resolved",
		len(rows), res.RepoCount, res.New, res.Resolved)
	if res.SeverityChanges > 0 {
		cmd.Printf(", %d severity change(s)", res.SeverityChanges)
	}
	if suppressed > 0 {
		cmd.Printf(" (%d dismissed, hidden)", suppressed)
	}
	cmd.Println(".")
	return nil
}

func filterBySeverity(rows []store.FindingView, minSev string) []store.FindingView {
	var out []store.FindingView
	for _, r := range rows {
		if config.SeverityAtLeast(r.Severity, minSev) {
			out = append(out, r)
		}
	}
	return out
}

// findingLess orders by exploited, then severity, then confidence, then direct.
func findingLess(a, b store.FindingView) bool {
	if a.Exploited != b.Exploited {
		return a.Exploited
	}
	if sa, sb := sevRank(a.Severity), sevRank(b.Severity); sa != sb {
		return sa > sb
	}
	if ca, cb := confRank(a.Confidence), confRank(b.Confidence); ca != cb {
		return ca > cb
	}
	if a.IsTransitive != b.IsTransitive {
		return !a.IsTransitive
	}
	return a.RepoName < b.RepoName
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func confRank(c string) int {
	switch c {
	case "confirmed":
		return 3
	case "probable":
		return 2
	case "possible":
		return 1
	default:
		return 0
	}
}

func filterRepos(repos []discover.Repo, cfg *config.Config, service, tag string) []discover.Repo {
	if service == "" && tag == "" {
		return repos
	}
	taggedNames := map[string]bool{}
	if tag != "" {
		for _, s := range cfg.Services {
			for _, t := range s.Tags {
				if t == tag {
					taggedNames[s.Name] = true
				}
			}
		}
	}
	var out []discover.Repo
	for _, r := range repos {
		if (service != "" && r.Name == service) || (tag != "" && taggedNames[r.Name]) {
			out = append(out, r)
		}
	}
	return out
}

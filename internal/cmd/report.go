package cmd

import (
	"os"
	"path/filepath"
	"time"

	"github.com/bmsandoval/vigil/internal/config"
	"github.com/bmsandoval/vigil/internal/report"
	"github.com/bmsandoval/vigil/internal/store"
	"github.com/spf13/cobra"
)

// newReportCmd renders a markdown report from the current findings, without
// rescanning.
func newReportCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "report",
		Short: "Render a markdown findings report",
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

			if out == "" {
				// stdout
				return writeReport(cmd.OutOrStdout(), st)
			}
			path, err := config.ExpandPath(out)
			if err != nil {
				return err
			}
			if err := writeReportFile(st, path); err != nil {
				return err
			}
			cmd.Printf("wrote report: %s\n", path)
			return nil
		},
	}
	c.Flags().StringVar(&out, "out", "", "write to a file instead of stdout")
	return c
}

// writeReport renders the markdown report to w.
func writeReport(w interface{ Write([]byte) (int, error) }, st *store.Store) error {
	findings, err := st.OpenFindings()
	if err != nil {
		return err
	}
	links := map[string][]string{}
	for _, f := range findings {
		if _, ok := links[f.AdvisoryID]; ok {
			continue
		}
		l, err := st.FixLinks(f.AdvisoryID)
		if err != nil {
			return err
		}
		links[f.AdvisoryID] = l
	}
	return report.Markdown(w, findings, report.Options{
		GeneratedAt: time.Now().Format("2006-01-02 15:04"),
		Links:       links,
	})
}

// writeReportFile writes the report to path, creating parent dirs.
func writeReportFile(st *store.Store, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeReport(f, st)
}

package cmd

import (
	"database/sql"

	"github.com/spf13/cobra"
)

// newStatusCmd prints a summary: watched services, advisory-mirror age, and
// open findings by severity.
func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show watched services, advisory-mirror age, and open findings",
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
			db := st.DB()

			cmd.Printf("config:    %s\n", cfg.Path())
			cmd.Printf("store:     %s\n", st.Path())
			cmd.Printf("services:  %d configured, %d discover roots\n",
				len(cfg.Services), len(cfg.Discovers))

			advCount := countRows(db, "SELECT COUNT(*) FROM advisories")
			lastSync := scalarString(db, "SELECT MAX(last_sync_at) FROM source_cursors")
			cmd.Printf("advisories: %d mirrored (last refresh: %s)\n", advCount, orNever(lastSync))

			lastScan := scalarString(db, "SELECT MAX(finished_at) FROM scans")
			cmd.Printf("last scan: %s\n", orNever(lastScan))

			openTotal := countRows(db, "SELECT COUNT(*) FROM findings WHERE status='open'")
			cmd.Printf("\nopen findings: %d\n", openTotal)
			if openTotal > 0 {
				for _, sev := range []string{"critical", "high", "medium", "low", "informational"} {
					n := countRows(db, "SELECT COUNT(*) FROM findings WHERE status='open' AND lower(severity)=?", sev)
					if n > 0 {
						cmd.Printf("  %-13s %d\n", sev+":", n)
					}
				}
				kev := countRows(db, "SELECT COUNT(*) FROM findings WHERE status='open' AND exploited=1")
				if kev > 0 {
					cmd.Printf("  %-13s %d\n", "exploited:", kev)
				}
				if n, _ := st.SuppressedCount(); n > 0 {
					cmd.Printf("  %-13s %d\n", "dismissed:", n)
				}
			}
			return nil
		},
	}
}

func countRows(db *sql.DB, query string, args ...any) int {
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		return 0
	}
	return n
}

func scalarString(db *sql.DB, query string, args ...any) string {
	var s sql.NullString
	if err := db.QueryRow(query, args...).Scan(&s); err != nil {
		return ""
	}
	return s.String
}

func orNever(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

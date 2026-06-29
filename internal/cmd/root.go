package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is overridden at build time via -ldflags "-X ...".
var version = "0.0.0-dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "vigil",
		Short: "Local-first vulnerability intelligence for your repositories",
		Long: `Vigil watches the repositories you keep on disk, maintains a local mirror
of public vulnerability advisories (OSV, CISA KEV, NVD), and tells you — with
a clear rationale and low false positives — whether a newly-disclosed
vulnerability actually affects code you have checked out.

Everything runs locally. Network access happens only while refreshing
advisories; scans work fully offline against the last-synced mirror.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&configPath, "config", defaultConfigPath(),
		"path to config.toml (or set $VIGIL_CONFIG)")

	root.AddCommand(
		newInitCmd(),
		newServiceCmd(),
		newRefreshCmd(),
		newScanCmd(),
		newStatusCmd(),
		newFindingsCmd(),
		newAckCmd(),
		newDismissCmd(),
		newResetCmd(),
		newReportCmd(),
		newWatchCmd(),
	)
	return root
}

// Execute runs the root command and exits non-zero on error.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "vigil:", err)
		os.Exit(1)
	}
}

package cmd

import (
	"os"

	"github.com/bmsandoval/vigil/internal/store"
	"github.com/spf13/cobra"
)

// newAckCmd, newDismissCmd, and newResetCmd manage a finding's state, keyed by
// the short id from `vigil findings`.

func newAckCmd() *cobra.Command {
	var note string
	c := &cobra.Command{
		Use:   "ack <id>",
		Short: "Acknowledge a finding (stays visible, marked acknowledged)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return setState(cmd, args[0], store.StateAcknowledged, "", note)
		},
	}
	c.Flags().StringVar(&note, "note", "", "optional note")
	return c
}

func newDismissCmd() *cobra.Command {
	var (
		note          string
		justification string
		wontFix       bool
	)
	c := &cobra.Command{
		Use:   "dismiss <id>",
		Short: "Dismiss a finding (hidden from default reports)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			state := store.StateDismissed
			if wontFix {
				state = store.StateWontFix
			}
			return setState(cmd, args[0], state, justification, note)
		},
	}
	c.Flags().StringVar(&note, "note", "", "optional note")
	c.Flags().StringVar(&justification, "justification", "",
		"VEX justification (e.g. component_not_present, not_reachable)")
	c.Flags().BoolVar(&wontFix, "wont-fix", false, "mark as won't-fix instead of dismissed")
	return c
}

func newResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset <id>",
		Short: "Clear a finding's state (re-activate it)",
		Args:  cobra.ExactArgs(1),
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

			fp, err := st.ResolveFingerprint(args[0])
			if err != nil {
				return err
			}
			if err := st.ClearFindingState(fp); err != nil {
				return err
			}
			cmd.Printf("reset %s\n", shortID(fp))
			return nil
		},
	}
}

func setState(cmd *cobra.Command, id, state, justification, note string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	fp, err := st.ResolveFingerprint(id)
	if err != nil {
		return err
	}
	summary, err := st.LookupFinding(fp)
	if err != nil {
		return err
	}
	if err := st.SetFindingState(fp, state, justification, note, currentUser()); err != nil {
		return err
	}
	cmd.Printf("%s %s — %s@%s (%s)\n", state, shortID(fp),
		summary.PackageName, summary.Version, summary.AdvisoryID)
	return nil
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return ""
}

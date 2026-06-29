package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/bmsandoval/vigil/internal/config"
	"github.com/spf13/cobra"
)

// newServiceCmd manages the services (on-disk repos) Vigil watches.
func newServiceCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "service",
		Aliases: []string{"svc"},
		Short:   "Manage the on-disk repositories Vigil watches",
	}
	c.AddCommand(newServiceAddCmd(), newServiceListCmd())
	return c
}

func newServiceAddCmd() *cobra.Command {
	var (
		ecosystems []string
		tags       []string
		minSev     string
	)
	c := &cobra.Command{
		Use:   "add <name> <path>",
		Short: "Add a repository to watch (appends a [[service]] block to config.toml)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, rawPath := args[0], args[1]

			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			for _, s := range cfg.Services {
				if s.Name == name {
					return fmt.Errorf("service %q already exists", name)
				}
			}
			absPath, err := config.ExpandPath(rawPath)
			if err != nil {
				return err
			}
			if info, err := os.Stat(absPath); err != nil || !info.IsDir() {
				return fmt.Errorf("path %q is not an accessible directory", absPath)
			}
			if minSev != "" && !config.ValidSeverity(minSev) {
				return fmt.Errorf("min-severity %q is not a valid severity", minSev)
			}

			block := renderServiceBlock(name, rawPath, ecosystems, tags, minSev)
			if err := appendToFile(cfg.Path(), block); err != nil {
				return err
			}

			// Re-validate so a malformed append fails loudly now, not later.
			if _, err := config.Load(cfg.Path()); err != nil {
				return fmt.Errorf("config invalid after add: %w", err)
			}
			cmd.Printf("added service %q -> %s\n", name, absPath)
			return nil
		},
	}
	c.Flags().StringSliceVar(&ecosystems, "ecosystems", nil, "restrict to these ecosystems (e.g. Go,npm); omit to auto-detect")
	c.Flags().StringSliceVar(&tags, "tags", nil, "labels for grouping (e.g. prod,backend)")
	c.Flags().StringVar(&minSev, "min-severity", "", "per-service reporting floor")
	return c
}

func newServiceListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured services",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if len(cfg.Services) == 0 && len(cfg.Discovers) == 0 {
				cmd.Println("no services configured — add one with 'vigil service add <name> <path>'")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tPATH\tECOSYSTEMS\tMIN-SEV\tTAGS")
			for _, s := range cfg.Services {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					s.Name, s.Path,
					orAuto(s.Ecosystems), cfg.EffectiveMinSeverity(s), join(s.Tags))
			}
			tw.Flush()
			for _, d := range cfg.Discovers {
				cmd.Printf("\ndiscover: %s (max_depth=%d, default min-sev=%s)\n",
					d.Root, d.MaxDepth, orDash(d.DefaultMinSeverity))
			}
			return nil
		},
	}
}

func renderServiceBlock(name, path string, ecos, tags []string, minSev string) string {
	var b strings.Builder
	b.WriteString("\n[[service]]\n")
	fmt.Fprintf(&b, "name = %q\n", name)
	fmt.Fprintf(&b, "path = %q\n", path)
	if len(ecos) > 0 {
		fmt.Fprintf(&b, "ecosystems = %s\n", tomlStringArray(ecos))
	}
	if minSev != "" {
		fmt.Fprintf(&b, "min_severity = %q\n", minSev)
	}
	if len(tags) > 0 {
		fmt.Fprintf(&b, "tags = %s\n", tomlStringArray(tags))
	}
	return b.String()
}

func appendToFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open config for append: %w", err)
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}

func tomlStringArray(xs []string) string {
	quoted := make([]string, len(xs))
	for i, x := range xs {
		quoted[i] = fmt.Sprintf("%q", x)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func orAuto(xs []string) string {
	if len(xs) == 0 {
		return "(auto)"
	}
	return join(xs)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func join(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	return strings.Join(xs, ",")
}

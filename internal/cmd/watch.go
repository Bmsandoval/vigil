package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/bmsandoval/vigil/internal/config"
	"github.com/bmsandoval/vigil/internal/discover"
	"github.com/bmsandoval/vigil/internal/scanner"
	"github.com/bmsandoval/vigil/internal/store"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
)

// newWatchCmd runs Vigil as a daemon: periodic advisory refresh, periodic (or
// on-change) scans, and notifications on new/severity-up/newly-exploited
// findings.
func newWatchCmd() *cobra.Command {
	var once bool
	c := &cobra.Command{
		Use:   "watch",
		Short: "Run continuously: scheduled refresh + scan with notifications",
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

			refreshEvery, _ := time.ParseDuration(cfg.Settings.RefreshEvery)
			onChange := cfg.Settings.ScanEvery == "on-change"
			scanEvery, _ := time.ParseDuration(cfg.Settings.ScanEvery)

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// Initial cycle so the daemon is useful immediately.
			cmd.Println("vigil watch: starting initial refresh + scan…")
			daemonRefresh(cmd, st, cfg)
			daemonScan(cmd, st, cfg)
			if once {
				return nil
			}

			refreshTick := time.NewTicker(maxDur(refreshEvery, time.Minute))
			defer refreshTick.Stop()
			var scanTick *time.Ticker
			var scanC <-chan time.Time
			if !onChange {
				scanTick = time.NewTicker(maxDur(scanEvery, time.Minute))
				defer scanTick.Stop()
				scanC = scanTick.C
			}

			// File watching for on-change scans (best-effort, debounced).
			fsEvents := make(chan struct{}, 1)
			if onChange {
				if w, err := startWatching(cfg); err == nil {
					defer w.Close()
					go debounceWatcher(ctx, w, fsEvents)
					cmd.Println("vigil watch: watching repositories for changes.")
				} else {
					fmt.Fprintf(cmd.ErrOrStderr(), "  file watch unavailable (%v); falling back to hourly scans\n", err)
					scanTick = time.NewTicker(time.Hour)
					defer scanTick.Stop()
					scanC = scanTick.C
				}
			}

			cmd.Printf("vigil watch: running (refresh every %s, scan %s). Ctrl-C to stop.\n",
				cfg.Settings.RefreshEvery, cfg.Settings.ScanEvery)
			for {
				select {
				case <-ctx.Done():
					cmd.Println("\nvigil watch: stopped.")
					return nil
				case <-refreshTick.C:
					daemonRefresh(cmd, st, cfg)
					daemonScan(cmd, st, cfg) // re-match after new advisories
				case <-scanC:
					daemonScan(cmd, st, cfg)
				case <-fsEvents:
					cmd.Println("vigil watch: change detected, scanning…")
					daemonScan(cmd, st, cfg)
				}
			}
		},
	}
	c.Flags().BoolVar(&once, "once", false, "run a single refresh+scan cycle and exit")
	return c
}

func daemonRefresh(cmd *cobra.Command, st *store.Store, cfg *config.Config) {
	ecos, err := resolveEcosystems(st, cfg.Sources.OSV.Ecosystems)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  refresh: %v\n", err)
		return
	}
	performRefresh(cmd, st, cfg, ecos, nil)
}

func daemonScan(cmd *cobra.Command, st *store.Store, cfg *config.Config) {
	if n, _ := st.CountAdvisories(); n == 0 {
		return // nothing to match against yet
	}
	repos, err := discover.Resolve(cfg)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  scan: %v\n", err)
		return
	}
	res, err := scanner.Run(st, repos, func(repo string, e error) {
		fmt.Fprintf(cmd.ErrOrStderr(), "  %s: %v\n", repo, e)
	})
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  scan: %v\n", err)
		return
	}
	disp := buildDispatcher(cfg, st, cmd.OutOrStdout(), true)
	dr := disp.Dispatch(res.Events)
	for _, e := range dr.Errors {
		fmt.Fprintf(cmd.ErrOrStderr(), "  notify: %v\n", e)
	}
	if res.New > 0 || res.SeverityChanges > 0 || dr.Sent > 0 {
		cmd.Printf("vigil watch: %d new, %d severity change(s), %d resolved, %d alert(s) at %s\n",
			res.New, res.SeverityChanges, res.Resolved, dr.Sent, time.Now().Format("15:04:05"))
	}
}

// startWatching adds each resolved repo root to a new fsnotify watcher.
func startWatching(cfg *config.Config) (*fsnotify.Watcher, error) {
	repos, err := discover.Resolve(cfg)
	if err != nil {
		return nil, err
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	added := 0
	for _, repo := range repos {
		if err := w.Add(repo.Path); err == nil {
			added++
		}
	}
	if added == 0 {
		w.Close()
		return nil, fmt.Errorf("no repositories to watch")
	}
	return w, nil
}

// debounceWatcher coalesces bursts of filesystem events into a single signal,
// so editor save-storms trigger one scan rather than dozens.
func debounceWatcher(ctx context.Context, w *fsnotify.Watcher, out chan<- struct{}) {
	var timer *time.Timer
	var timerC <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-w.Events:
			if !ok {
				return
			}
			if timer == nil {
				timer = time.NewTimer(2 * time.Second)
				timerC = timer.C
			} else {
				timer.Reset(2 * time.Second)
			}
		case <-timerC:
			select {
			case out <- struct{}{}:
			default:
			}
		case <-w.Errors:
		}
	}
}

func maxDur(d, floor time.Duration) time.Duration {
	if d < floor {
		return floor
	}
	return d
}

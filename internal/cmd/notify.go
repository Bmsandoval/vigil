package cmd

import (
	"io"

	"github.com/bmsandoval/vigil/internal/config"
	"github.com/bmsandoval/vigil/internal/notify"
	"github.com/bmsandoval/vigil/internal/store"
)

// buildDispatcher assembles the configured notification channels. When
// includeTerminal is set, a terminal channel writes alert lines to w (used by
// the daemon, where the terminal is the primary feed; the scan command already
// prints a findings table, so it omits it).
func buildDispatcher(cfg *config.Config, st *store.Store, w io.Writer, includeTerminal bool) *notify.Dispatcher {
	var channels []notify.Channel

	if includeTerminal {
		channels = append(channels, notify.TerminalChannel{W: w})
	}
	if cfg.Notify.Desktop.Enabled {
		channels = append(channels, notify.DesktopChannel{
			MinSev:           minSevFromOnly(cfg.Notify.Desktop.Only),
			IncludeExploited: onlyContainsKEV(cfg.Notify.Desktop.Only),
		})
	}
	if cfg.Notify.Slack.Enabled && cfg.Notify.Slack.WebhookURL != "" {
		channels = append(channels, notify.NewWebhookChannel(
			"slack", cfg.Notify.Slack.WebhookURL, "slack", cfg.Notify.Slack.MinSeverity, false, nil))
	}

	return &notify.Dispatcher{Store: st, Channels: channels}
}

// minSevFromOnly extracts a severity floor from a desktop "only" list such as
// ["critical","exploited"] → "critical".
func minSevFromOnly(only []string) string {
	for _, o := range only {
		if config.ValidSeverity(o) {
			return o
		}
	}
	return ""
}

func onlyContainsKEV(only []string) bool {
	for _, o := range only {
		if o == "exploited" || o == "kev" {
			return true
		}
	}
	return false
}

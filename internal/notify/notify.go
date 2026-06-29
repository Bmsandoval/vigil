// Package notify dispatches matcher events to output channels. Dispatch is
// diff-driven (only changed findings produce events) and deduplicated via the
// store's notifications_log, so a finding alerts at most once per channel per
// event type — the core defense against alert fatigue.
package notify

import (
	"fmt"

	"github.com/bmsandoval/vigil/internal/match"
	"github.com/bmsandoval/vigil/internal/store"
)

// Channel is a notification sink.
type Channel interface {
	// Name identifies the channel in the dedup log (stable across runs).
	Name() string
	// Wants reports whether this channel cares about the event (severity /
	// exploited filtering).
	Wants(ev match.Event) bool
	// Send delivers a single event.
	Send(ev match.Event) error
}

// Dispatcher fans events out to channels with per-channel dedup.
type Dispatcher struct {
	Store    *store.Store
	Channels []Channel
}

// Result counts what was dispatched.
type Result struct {
	Sent    int
	Skipped int // already notified or filtered out
	Errors  []error
}

// Dispatch sends each event to every interested channel that has not already
// seen it, recording each successful send for future dedup.
func (d *Dispatcher) Dispatch(events []match.Event) Result {
	var res Result
	for _, ev := range events {
		for _, ch := range d.Channels {
			if !ch.Wants(ev) {
				res.Skipped++
				continue
			}
			already, err := d.Store.AlreadyNotified(ev.Fingerprint, ch.Name(), ev.Type)
			if err != nil {
				res.Errors = append(res.Errors, err)
				continue
			}
			if already {
				res.Skipped++
				continue
			}
			if err := ch.Send(ev); err != nil {
				res.Errors = append(res.Errors, fmt.Errorf("%s: %w", ch.Name(), err))
				continue
			}
			if err := d.Store.RecordNotification(ev.Fingerprint, ch.Name(), ev.Type); err != nil {
				res.Errors = append(res.Errors, err)
				continue
			}
			res.Sent++
		}
	}
	return res
}

// severityRank orders severities for channel min-severity filtering.
func severityRank(s string) int {
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

// atLeast reports whether got meets the floor (empty floor = no filter).
func atLeast(got, floor string) bool {
	if floor == "" {
		return true
	}
	return severityRank(got) >= severityRank(floor)
}

// wantsEvent applies a channel's filter: pass if the severity meets the floor,
// OR (when includeExploited) the event is actively exploited regardless of
// severity. This gives "only [critical, exploited]" its OR semantics.
func wantsEvent(ev match.Event, minSev string, includeExploited bool) bool {
	if includeExploited && ev.Exploited {
		return true
	}
	return atLeast(ev.Severity, minSev)
}

// describe renders a human-readable one-line summary of an event.
func describe(ev match.Event) string {
	verb := map[string]string{
		match.EventNew:            "New vulnerability",
		match.EventSeverityUp:     "Severity increased",
		match.EventNewlyExploited: "Now actively exploited",
	}[ev.Type]
	if verb == "" {
		verb = "Vulnerability"
	}
	kev := ""
	if ev.Exploited {
		kev = " ⚠ KEV"
	}
	fix := "no fix recorded"
	if ev.FixedVer != "" {
		fix = "fix: " + ev.FixedVer
	}
	return fmt.Sprintf("%s [%s]%s — %s: %s@%s (%s, %s)",
		verb, ev.Severity, kev, ev.RepoName, ev.PackageName, ev.Version, ev.AdvisoryID, fix)
}

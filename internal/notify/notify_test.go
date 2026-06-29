package notify

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/bmsandoval/vigil/internal/match"
	"github.com/bmsandoval/vigil/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "vigil.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// captureChannel records events it receives.
type captureChannel struct {
	name     string
	minSev   string
	exploit  bool
	received []match.Event
}

func (c *captureChannel) Name() string              { return c.name }
func (c *captureChannel) Wants(ev match.Event) bool { return wantsEvent(ev, c.minSev, c.exploit) }
func (c *captureChannel) Send(ev match.Event) error {
	c.received = append(c.received, ev)
	return nil
}

func ev(t, sev, fp string, exploited bool) match.Event {
	return match.Event{Type: t, Severity: sev, Fingerprint: fp, Exploited: exploited,
		RepoName: "r", PackageName: "p", Version: "1.0.0", AdvisoryID: "GHSA-x"}
}

func TestDispatchDedup(t *testing.T) {
	st := newStore(t)
	ch := &captureChannel{name: "cap"}
	d := &Dispatcher{Store: st, Channels: []Channel{ch}}

	events := []match.Event{ev(match.EventNew, "high", "fp1", false)}
	r1 := d.Dispatch(events)
	if r1.Sent != 1 {
		t.Fatalf("first dispatch sent = %d, want 1", r1.Sent)
	}
	// Same event again → deduped via notifications_log.
	r2 := d.Dispatch(events)
	if r2.Sent != 0 || r2.Skipped != 1 {
		t.Errorf("second dispatch should dedup: %+v", r2)
	}
	if len(ch.received) != 1 {
		t.Errorf("channel should have received exactly 1 event, got %d", len(ch.received))
	}

	// A different event type for the same finding is NOT deduped.
	r3 := d.Dispatch([]match.Event{ev(match.EventSeverityUp, "critical", "fp1", false)})
	if r3.Sent != 1 {
		t.Errorf("different event type should send: %+v", r3)
	}
}

func TestDispatchSeverityFilter(t *testing.T) {
	st := newStore(t)
	highOnly := &captureChannel{name: "high", minSev: "high"}
	kev := &captureChannel{name: "kev", minSev: "critical", exploit: true}
	d := &Dispatcher{Store: st, Channels: []Channel{highOnly, kev}}

	d.Dispatch([]match.Event{
		ev(match.EventNew, "low", "a", false),   // below high → neither (kev: not exploited)
		ev(match.EventNew, "high", "b", false),  // highOnly yes; kev no (not critical/exploited)
		ev(match.EventNew, "medium", "c", true), // highOnly no; kev yes (exploited)
	})
	if len(highOnly.received) != 1 || highOnly.received[0].Fingerprint != "b" {
		t.Errorf("highOnly got %+v", highOnly.received)
	}
	if len(kev.received) != 1 || kev.received[0].Fingerprint != "c" {
		t.Errorf("kev got %+v", kev.received)
	}
}

func TestWebhookChannel(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ch := NewWebhookChannel("slack", srv.URL, "slack", "high", false, srv.Client())
	if ch.Wants(ev(match.EventNew, "low", "x", false)) {
		t.Error("low should be filtered for high webhook")
	}
	if err := ch.Send(ev(match.EventNew, "critical", "x", false)); err != nil {
		t.Fatalf("send: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("webhook hits = %d, want 1", hits)
	}
}

func TestDesktopChannelInjectableNotifier(t *testing.T) {
	var got string
	ch := DesktopChannel{Notifier: func(title, body string) error { got = title + "|" + body; return nil }}
	if err := ch.Send(ev(match.EventNewlyExploited, "critical", "x", true)); err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Error("notifier was not invoked")
	}
}

package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"runtime"

	"github.com/bmsandoval/vigil/internal/match"
)

// TerminalChannel prints events to a writer.
type TerminalChannel struct {
	W                io.Writer
	MinSev           string
	IncludeExploited bool
}

func (TerminalChannel) Name() string { return "terminal" }

func (c TerminalChannel) Wants(ev match.Event) bool {
	return wantsEvent(ev, c.MinSev, c.IncludeExploited)
}

func (c TerminalChannel) Send(ev match.Event) error {
	_, err := fmt.Fprintln(c.W, "  • "+describe(ev))
	return err
}

// WebhookChannel posts events to a Slack- or Discord-style incoming webhook.
type WebhookChannel struct {
	URL              string
	Kind             string // "slack" (default) or "discord"
	MinSev           string
	IncludeExploited bool
	HTTP             *http.Client
	label            string
}

// NewWebhookChannel builds a webhook channel with a stable dedup name.
func NewWebhookChannel(name, url, kind, minSev string, includeExploited bool, client *http.Client) *WebhookChannel {
	return &WebhookChannel{URL: url, Kind: kind, MinSev: minSev, IncludeExploited: includeExploited, HTTP: client, label: name}
}

func (c *WebhookChannel) Name() string {
	if c.label != "" {
		return c.label
	}
	return "webhook"
}

func (c *WebhookChannel) Wants(ev match.Event) bool {
	return wantsEvent(ev, c.MinSev, c.IncludeExploited)
}

func (c *WebhookChannel) Send(ev match.Event) error {
	field := "text" // Slack
	if c.Kind == "discord" {
		field = "content"
	}
	payload, err := json.Marshal(map[string]string{field: "Vigil: " + describe(ev)})
	if err != nil {
		return err
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Post(c.URL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %s", resp.Status)
	}
	return nil
}

// DesktopChannel raises an OS notification. The Notifier is injectable so the
// dispatch logic is testable without a real desktop; it defaults to a
// platform-native command.
type DesktopChannel struct {
	MinSev           string
	IncludeExploited bool
	Notifier         func(title, body string) error
}

func (DesktopChannel) Name() string { return "desktop" }

func (c DesktopChannel) Wants(ev match.Event) bool {
	return wantsEvent(ev, c.MinSev, c.IncludeExploited)
}

func (c DesktopChannel) Send(ev match.Event) error {
	notify := c.Notifier
	if notify == nil {
		notify = platformNotify
	}
	title := "Vigil: " + ev.Severity + " in " + ev.RepoName
	return notify(title, describe(ev))
}

// platformNotify uses a best-effort native notifier per OS. Failures are
// non-fatal to the dispatcher (the event is simply not recorded as sent).
func platformNotify(title, body string) error {
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf("display notification %q with title %q", body, title)
		return exec.Command("osascript", "-e", script).Run()
	case "linux":
		return exec.Command("notify-send", title, body).Run()
	default:
		return fmt.Errorf("desktop notifications unsupported on %s", runtime.GOOS)
	}
}

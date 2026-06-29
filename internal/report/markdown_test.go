package report

import (
	"strings"
	"testing"

	"github.com/bmsandoval/vigil/internal/store"
)

func TestMarkdownGroupsAndPrioritizes(t *testing.T) {
	findings := []store.FindingView{
		{RepoName: "api", PackageName: "lodash", Version: "4.17.20", Severity: "high",
			Confidence: "confirmed", AdvisoryID: "GHSA-1", FixedVersion: "4.17.21", Rationale: "because reasons"},
		{RepoName: "api", PackageName: "express", Version: "4.0.0", Severity: "critical",
			Confidence: "confirmed", AdvisoryID: "GHSA-2", Exploited: true},
		{RepoName: "web", PackageName: "minimist", Version: "1.0.0", Severity: "low",
			Confidence: "probable", AdvisoryID: "GHSA-3"},
		// dismissed → must not appear in the body
		{RepoName: "web", PackageName: "noise", Version: "0.1.0", Severity: "high",
			AdvisoryID: "GHSA-4", State: store.StateDismissed},
	}
	var sb strings.Builder
	if err := Markdown(&sb, findings, Options{GeneratedAt: "2026-06-28 10:00",
		Links: map[string][]string{"GHSA-1": {"https://example/fix"}}}); err != nil {
		t.Fatal(err)
	}
	out := sb.String()

	for _, want := range []string{
		"# Vigil vulnerability report",
		"## api", "## web",
		"lodash@4.17.20", "express@4.0.0",
		"EXPLOITED (KEV)",
		"upgrade to 4.17.21",
		"https://example/fix",
		"https://osv.dev/vulnerability/GHSA-1",
		"1 dismissed/won't-fix",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "GHSA-4") || strings.Contains(out, "noise@") {
		t.Error("dismissed finding should not appear in the report body")
	}

	// Within repo "api", critical+exploited express must come before high lodash.
	if strings.Index(out, "express@4.0.0") > strings.Index(out, "lodash@4.17.20") {
		t.Error("exploited critical should be ordered before high")
	}
}

func TestMarkdownEmpty(t *testing.T) {
	var sb strings.Builder
	if err := Markdown(&sb, nil, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "No active findings") {
		t.Errorf("empty report should say so:\n%s", sb.String())
	}
}

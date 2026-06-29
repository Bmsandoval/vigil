// Package report renders findings into shareable artifacts. The markdown report
// is the portable output: grouped by repository, ordered by priority, with the
// rationale, remediation, and links for each finding.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bmsandoval/vigil/internal/store"
)

// Options controls report rendering.
type Options struct {
	GeneratedAt     string
	IncludeResolved bool
	// Links maps an advisory id to reference URLs (fix/commit/advisory).
	Links map[string][]string
}

var severityOrder = map[string]int{
	"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0,
}

// Markdown writes a findings report. Suppressed findings (dismissed/wont_fix)
// are summarized separately rather than listed inline.
func Markdown(w io.Writer, findings []store.FindingView, opts Options) error {
	var active, suppressed []store.FindingView
	for _, f := range findings {
		if f.Suppressed() {
			suppressed = append(suppressed, f)
		} else {
			active = append(active, f)
		}
	}

	bw := &errWriter{w: w}
	bw.printf("# Vigil vulnerability report\n\n")
	if opts.GeneratedAt != "" {
		bw.printf("_Generated %s._\n\n", opts.GeneratedAt)
	}

	bw.printf("## Summary\n\n")
	bw.printf("- **%d** active finding(s)\n", len(active))
	if exploited := countExploited(active); exploited > 0 {
		bw.printf("- **%d** actively exploited (CISA KEV) ⚠\n", exploited)
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "informational"} {
		if n := countSeverity(active, sev); n > 0 {
			bw.printf("- %s: %d\n", titleCase(sev), n)
		}
	}
	if len(suppressed) > 0 {
		bw.printf("- %d dismissed/won't-fix (not detailed below)\n", len(suppressed))
	}
	bw.printf("\n")

	byRepo := groupByRepo(active)
	repos := make([]string, 0, len(byRepo))
	for r := range byRepo {
		repos = append(repos, r)
	}
	sort.Strings(repos)

	for _, repo := range repos {
		items := byRepo[repo]
		sort.Slice(items, func(i, j int) bool { return priorityLess(items[i], items[j]) })
		bw.printf("## %s\n\n", repo)
		for _, f := range items {
			renderFinding(bw, f, opts.Links[f.AdvisoryID])
		}
	}

	if len(active) == 0 {
		bw.printf("No active findings. 🎉\n")
	}
	return bw.err
}

func renderFinding(bw *errWriter, f store.FindingView, links []string) {
	kev := ""
	if f.Exploited {
		kev = " ⚠ **EXPLOITED (KEV)**"
	}
	dep := "direct"
	if f.IsTransitive {
		dep = "transitive"
	}
	bw.printf("### %s `%s@%s`%s\n\n", strings.ToUpper(f.Severity), f.PackageName, f.Version, kev)
	bw.printf("- **Advisory:** %s\n", f.AdvisoryID)
	bw.printf("- **Dependency:** %s (%s) · confidence: %s\n", dep, f.Ecosystem, f.Confidence)
	if f.FixedVersion != "" {
		bw.printf("- **Fix:** upgrade to %s", f.FixedVersion)
		if f.LatestVersion != "" && f.LatestVersion != f.FixedVersion {
			bw.printf(" (latest: %s)", f.LatestVersion)
		}
		bw.printf("\n")
	} else {
		bw.printf("- **Fix:** none recorded — see advisory for mitigation\n")
	}
	if f.State != "" {
		bw.printf("- **Status:** %s", f.State)
		if f.StateNote != "" {
			bw.printf(" — %s", f.StateNote)
		}
		bw.printf("\n")
	}
	if f.Rationale != "" {
		bw.printf("- **Why:** %s\n", f.Rationale)
	}
	allLinks := append([]string{"https://osv.dev/vulnerability/" + f.AdvisoryID}, links...)
	bw.printf("- **Links:** %s\n", strings.Join(dedupe(allLinks), " · "))
	bw.printf("\n")
}

func groupByRepo(fs []store.FindingView) map[string][]store.FindingView {
	m := map[string][]store.FindingView{}
	for _, f := range fs {
		m[f.RepoName] = append(m[f.RepoName], f)
	}
	return m
}

func priorityLess(a, b store.FindingView) bool {
	if a.Exploited != b.Exploited {
		return a.Exploited
	}
	if severityOrder[a.Severity] != severityOrder[b.Severity] {
		return severityOrder[a.Severity] > severityOrder[b.Severity]
	}
	return a.PackageName < b.PackageName
}

func countSeverity(fs []store.FindingView, sev string) int {
	n := 0
	for _, f := range fs {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func countExploited(fs []store.FindingView) int {
	n := 0
	for _, f := range fs {
		if f.Exploited {
			n++
		}
	}
	return n
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

// errWriter accumulates the first write error so callers check once.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

// Package match is the impact-analysis engine. It joins the repository
// inventory to the advisory mirror and decides, for each package, whether a
// vulnerability actually applies — separating Severity (how bad, from the
// advisory) from Confidence (how sure we are it affects this repo). That
// separation is the central control against false positives.
package match

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/bmsandoval/vigil/internal/reachability"
	"github.com/bmsandoval/vigil/internal/store"
	"github.com/bmsandoval/vigil/internal/version"
)

// Confidence levels, from strongest to weakest.
const (
	Confirmed = "confirmed" // pinned version cleanly inside an affected range
	Probable  = "probable"  // matched, but evaluation was partially degraded
	Possible  = "possible"  // name matched; version evaluation unavailable
)

// Engine runs matching against a store.
type Engine struct {
	Store *store.Store
	// Reachability, when set, maps a repo id to a govulncheck report used to
	// annotate Go findings as called/imported. Repos without an entry are left
	// unannotated.
	Reachability map[int64]*reachability.Report
}

// Event types for notifications.
const (
	EventNew            = "new"
	EventSeverityUp     = "severity_up"
	EventNewlyExploited = "newly_exploited"
)

// Event is a notable change in a finding, emitted for notification dispatch.
type Event struct {
	Type        string
	Fingerprint string
	RepoName    string
	PackageName string
	Version     string
	AdvisoryID  string
	Severity    string
	Exploited   bool
	FixedVer    string
}

// Result summarizes a matching run.
type Result struct {
	ScanID          int64
	RepoCount       int
	Findings        int
	New             int
	Resolved        int
	SeverityChanges int
	Events          []Event
}

// Run matches the current inventory against the advisory mirror, persists
// findings, and resolves any that no longer apply. repoIDs optionally restricts
// the scan; empty means all enabled repos.
func (e *Engine) Run(repoIDs []int64) (Result, error) {
	var res Result

	scanID, err := e.Store.CreateScan()
	if err != nil {
		return res, err
	}
	res.ScanID = scanID

	instances, err := e.Store.AllInstances(repoIDs)
	if err != nil {
		return res, err
	}

	repos := map[int64]bool{}
	advCache := map[string][]store.AffectedAdvisory{}
	exploitCache := map[string]bool{}

	for _, in := range instances {
		repos[in.RepoID] = true

		key := in.Ecosystem + "\x00" + in.PackageName
		advs, ok := advCache[key]
		if !ok {
			advs, err = e.Store.AffectedAdvisoriesFor(in.Ecosystem, in.PackageName)
			if err != nil {
				return res, err
			}
			advCache[key] = advs
		}

		// Collect candidate findings per instance, collapsing advisories that
		// are aliases of the same underlying vulnerability (e.g. a GHSA and a
		// GO-/PYSEC record sharing a CVE) into one finding.
		candidates := map[string]candidate{}
		for _, adv := range advs {
			finding, vulnKey, ok := evaluate(in, adv)
			if !ok {
				continue
			}
			exploited, seen := exploitCache[adv.AdvisoryID]
			if !seen {
				exploited, err = e.Store.IsExploited(adv.AdvisoryID)
				if err != nil {
					return res, err
				}
				exploitCache[adv.AdvisoryID] = exploited
			}
			finding.Exploited = exploited
			if exploited {
				finding.Rationale += " Listed in CISA KEV (actively exploited)."
			}
			if rep := e.Reachability[in.RepoID]; rep != nil && rep.Ran && in.Ecosystem == "Go" {
				ids := append([]string{adv.AdvisoryID}, adv.Aliases...)
				switch rep.Lookup(ids...) {
				case reachability.LevelCalled:
					finding.Reachability = "called"
					finding.Rationale += " Reachable: an affected symbol is called (govulncheck)."
				case reachability.LevelImported:
					finding.Reachability = "imported"
					finding.Rationale += " Not reachable: imported but no affected symbol is called (govulncheck)."
				}
			}
			cand := candidate{finding: finding, adv: adv}
			if existing, dup := candidates[vulnKey]; dup {
				candidates[vulnKey] = mergeCandidate(existing, cand)
			} else {
				candidates[vulnKey] = cand
			}
		}

		for _, c := range candidates {
			delta, err := e.Store.UpsertFinding(scanID, c.finding)
			if err != nil {
				return res, err
			}
			res.Findings++
			if delta.IsNew {
				res.New++
			}
			if delta.SeverityUp {
				res.SeverityChanges++
			}
			res.Events = append(res.Events, eventsFor(in, c.adv, c.finding, delta)...)
		}
	}

	resolved, err := e.Store.ResolveStale(scanID)
	if err != nil {
		return res, err
	}
	res.Resolved = resolved
	res.RepoCount = len(repos)
	if err := e.Store.FinishScan(scanID, res.RepoCount, res.Findings); err != nil {
		return res, err
	}
	return res, nil
}

// eventsFor turns a finding delta into notification events. A newly-exploited
// finding is the highest-signal event and is emitted even if not brand new.
func eventsFor(in store.Instance, adv store.AffectedAdvisory, f store.Finding, d store.FindingDelta) []Event {
	base := Event{
		Fingerprint: f.Fingerprint, RepoName: in.RepoName, PackageName: in.PackageName,
		Version: in.Version, AdvisoryID: adv.AdvisoryID, Severity: f.Severity,
		Exploited: f.Exploited, FixedVer: f.FixedVersion,
	}
	var out []Event
	if d.IsNew {
		e := base
		e.Type = EventNew
		out = append(out, e)
	}
	if d.SeverityUp && !d.IsNew {
		e := base
		e.Type = EventSeverityUp
		out = append(out, e)
	}
	if d.NewlyExploited && !d.IsNew {
		e := base
		e.Type = EventNewlyExploited
		out = append(out, e)
	}
	return out
}

// candidate pairs a finding with the advisory it came from, during per-instance
// alias deduplication.
type candidate struct {
	finding store.Finding
	adv     store.AffectedAdvisory
}

// mergeCandidate collapses two alias findings into one, keeping the
// higher-signal advisory and OR-ing exploitation.
func mergeCandidate(a, b candidate) candidate {
	winner, loser := a, b
	if findingStronger(b.finding, a.finding) {
		winner, loser = b, a
	}
	winner.finding.Exploited = a.finding.Exploited || b.finding.Exploited
	// Prefer any recorded fix between the two.
	if winner.finding.FixedVersion == "" && loser.finding.FixedVersion != "" {
		winner.finding.FixedVersion = loser.finding.FixedVersion
	}
	// Keep the strongest reachability signal (called > imported > unknown).
	if reachRank(loser.finding.Reachability) > reachRank(winner.finding.Reachability) {
		winner.finding.Reachability = loser.finding.Reachability
	}
	if winner.finding.Exploited && !strings.Contains(winner.finding.Rationale, "KEV") {
		winner.finding.Rationale += " Listed in CISA KEV (actively exploited)."
	}
	return winner
}

// findingStronger reports whether x should win over y when merging aliases:
// higher severity, then confirmed confidence, then has-fix.
func findingStronger(x, y store.Finding) bool {
	if sx, sy := sevRankInt(x.Severity), sevRankInt(y.Severity); sx != sy {
		return sx > sy
	}
	if cx, cy := confRankInt(x.Confidence), confRankInt(y.Confidence); cx != cy {
		return cx > cy
	}
	return x.FixedVersion != "" && y.FixedVersion == ""
}

// vulnKey returns the canonical identity for alias dedup: the first CVE alias if
// present, else the advisory id. Two records sharing a CVE collapse together.
func vulnKey(adv store.AffectedAdvisory) string {
	for _, a := range adv.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return adv.AdvisoryID
}

func sevRankInt(s string) int {
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

func confRankInt(c string) int {
	switch c {
	case Confirmed:
		return 3
	case Probable:
		return 2
	default:
		return 1
	}
}

func reachRank(r string) int {
	switch r {
	case "called":
		return 2
	case "imported":
		return 1
	default:
		return 0
	}
}

// evaluate decides whether an advisory affects an instance and, if so, builds
// the finding plus its canonical vuln key. ok=false means not affected.
func evaluate(in store.Instance, adv store.AffectedAdvisory) (store.Finding, string, bool) {
	if adv.Withdrawn {
		return store.Finding{}, "", false
	}

	comp, hasComp := version.For(in.Ecosystem)
	matched, confidence := false, Possible

	// Exact membership in the explicit affected-versions list is unambiguous.
	if containsExact(adv.AffectedVers, in.Version) {
		matched, confidence = true, Confirmed
	}

	// Range evaluation with the ecosystem comparator.
	if hasComp && comp.Valid(in.Version) {
		degraded := false
		for _, r := range adv.Ranges {
			if strings.EqualFold(r.Type, "GIT") {
				continue // commit ranges can't be evaluated by version
			}
			ok, err := version.InRange(comp, in.Version, r.Introduced, r.Fixed, r.LastAffected)
			if err != nil {
				degraded = true
				continue
			}
			if ok {
				matched = true
				if confidence != Confirmed {
					confidence = Confirmed
				}
			}
		}
		if matched && degraded && confidence != Confirmed {
			confidence = Probable
		}
	} else if matched {
		// matched only via explicit list, but we couldn't parse the version
		confidence = Probable
	}

	if !matched {
		return store.Finding{}, "", false
	}

	severity := adv.SeverityLabel
	if severity == "" {
		severity = "informational"
	}

	var minSafe, latest string
	if hasComp {
		minSafe, latest = version.MinFixedAbove(comp, in.Version, adv.FixedVers)
	} else if len(adv.FixedVers) > 0 {
		latest = adv.FixedVers[len(adv.FixedVers)-1]
	}

	key := vulnKey(adv)
	f := store.Finding{
		Fingerprint:   fingerprint(in.RepoID, in.Ecosystem, in.PackageName, in.Version, key),
		RepoID:        in.RepoID,
		InstanceID:    in.InstanceID,
		AdvisoryID:    adv.AdvisoryID,
		Severity:      severity,
		Confidence:    confidence,
		IsTransitive:  !in.IsDirect,
		FixedVersion:  minSafe,
		LatestVersion: latest,
		Rationale:     rationale(in, adv, severity, confidence, minSafe),
	}
	return f, key, true
}

func rationale(in store.Instance, adv store.AffectedAdvisory, severity, confidence, minSafe string) string {
	dep := "direct"
	if !in.IsDirect {
		dep = "transitive"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s@%s (%s, %s) is affected by %s",
		in.PackageName, in.Version, in.Ecosystem, dep, adv.AdvisoryID)
	if severity != "informational" {
		fmt.Fprintf(&b, " [%s]", severity)
	}
	if adv.CVSSScore > 0 {
		fmt.Fprintf(&b, " (CVSS %.1f)", adv.CVSSScore)
	}
	b.WriteString(".")
	if minSafe != "" {
		fmt.Fprintf(&b, " Fixed in %s.", minSafe)
	} else {
		b.WriteString(" No fixed version is recorded.")
	}
	fmt.Fprintf(&b, " Confidence: %s (%s).", confidence, locatorOr(in))
	return b.String()
}

func locatorOr(in store.Instance) string {
	if in.Locator != "" {
		return "pinned at " + in.Locator
	}
	return "pinned version from " + in.ManifestKind
}

func containsExact(versions []string, v string) bool {
	for _, x := range versions {
		if x == v {
			return true
		}
	}
	return false
}

func fingerprint(repoID int64, ecosystem, name, ver, advisoryID string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s",
		repoID, ecosystem, name, ver, advisoryID)))
	return hex.EncodeToString(h[:16])
}

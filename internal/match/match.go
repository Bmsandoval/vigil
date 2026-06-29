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

		for _, adv := range advs {
			finding, ok := evaluate(in, adv)
			if !ok {
				continue
			}
			exploited, ok := exploitCache[adv.AdvisoryID]
			if !ok {
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

			delta, err := e.Store.UpsertFinding(scanID, finding)
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
			res.Events = append(res.Events, eventsFor(in, adv, finding, delta)...)
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

// evaluate decides whether an advisory affects an instance and, if so, builds
// the finding. It returns ok=false when the instance is not affected.
func evaluate(in store.Instance, adv store.AffectedAdvisory) (store.Finding, bool) {
	if adv.Withdrawn {
		return store.Finding{}, false
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
		return store.Finding{}, false
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

	f := store.Finding{
		Fingerprint:   fingerprint(in.RepoID, in.Ecosystem, in.PackageName, in.Version, adv.AdvisoryID),
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
	return f, true
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

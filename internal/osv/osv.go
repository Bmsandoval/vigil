// Package osv models the OSV (Open Source Vulnerability) schema and normalizes
// raw records into the flat shape Vigil stores and matches against.
//
// OSV is the canonical interchange format: GitHub advisories, PyPA, RustSec,
// the Go vuln DB, and many ecosystem feeds are all published in it. The key
// fields for impact analysis are affected[].package (ecosystem + name) and
// affected[].ranges (introduced/fixed/last_affected events).
package osv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Record is a raw OSV JSON record (the subset Vigil consumes).
type Record struct {
	ID               string         `json:"id"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Aliases          []string       `json:"aliases"`
	Modified         string         `json:"modified"`
	Published        string         `json:"published"`
	Withdrawn        string         `json:"withdrawn"`
	Severity         []Severity     `json:"severity"`
	Affected         []Affected     `json:"affected"`
	References       []Reference    `json:"references"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type Severity struct {
	Type  string `json:"type"`  // e.g. "CVSS_V3", "CVSS_V4"
	Score string `json:"score"` // the CVSS vector string
}

type Affected struct {
	Package          Package        `json:"package"`
	Ranges           []Range        `json:"ranges"`
	Versions         []string       `json:"versions"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl"`
}

type Range struct {
	Type   string  `json:"type"` // SEMVER | ECOSYSTEM | GIT
	Events []Event `json:"events"`
}

// Event is a single range boundary; exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// ── Normalized model (what the store persists) ──────────────────────────────

// Advisory is the flattened, storage-ready form of a Record.
type Advisory struct {
	ID            string
	Source        string
	Summary       string
	Details       string
	SeverityLabel string // CRITICAL/HIGH/MEDIUM/LOW (qualitative)
	CVSSVector    string
	CVSSScore     float64
	Published     string
	Modified      string
	Withdrawn     string
	ContentHash   string
	RawJSON       string
	Aliases       []string
	Affected      []NormAffected
	References    []NormReference
}

type NormAffected struct {
	Ecosystem        string
	PackageName      string
	Versions         []string // explicit affected versions
	FixedVersions    []string // collected from fixed events, for remediation
	DatabaseSpecific string   // JSON blob
	Ranges           []NormRange
}

type NormRange struct {
	Type         string
	Introduced   string
	Fixed        string
	LastAffected string
}

type NormReference struct {
	Kind string
	URL  string
}

// ParseRecord unmarshals a single OSV JSON document.
func ParseRecord(data []byte) (*Record, error) {
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Normalize flattens a Record into an Advisory, computing the content hash from
// the raw bytes so later refreshes can detect changes (a revised advisory has
// different bytes → different hash → "changed").
func (r *Record) Normalize(rawJSON []byte) Advisory {
	sum := sha256.Sum256(rawJSON)
	adv := Advisory{
		ID:            r.ID,
		Source:        sourceFromID(r.ID),
		Summary:       r.Summary,
		Details:       r.Details,
		SeverityLabel: r.severityLabel(),
		CVSSVector:    r.cvssVector(),
		Published:     r.Published,
		Modified:      r.Modified,
		Withdrawn:     r.Withdrawn,
		ContentHash:   hex.EncodeToString(sum[:]),
		RawJSON:       string(rawJSON),
		Aliases:       r.Aliases,
	}
	if v := adv.CVSSVector; v != "" {
		adv.CVSSScore = CVSSBaseScore(v)
		if adv.SeverityLabel == "" {
			adv.SeverityLabel = LabelFromScore(adv.CVSSScore)
		}
	}
	for _, a := range r.Affected {
		na := NormAffected{
			Ecosystem:        a.Package.Ecosystem,
			PackageName:      a.Package.Name,
			Versions:         a.Versions,
			DatabaseSpecific: jsonString(a.DatabaseSpecific),
		}
		for _, rng := range a.Ranges {
			var introduced string
			for _, e := range rng.Events {
				switch {
				case e.Introduced != "":
					introduced = e.Introduced
				case e.Fixed != "":
					na.Ranges = append(na.Ranges, NormRange{Type: rng.Type, Introduced: introduced, Fixed: e.Fixed})
					na.FixedVersions = append(na.FixedVersions, e.Fixed)
					introduced = ""
				case e.LastAffected != "":
					na.Ranges = append(na.Ranges, NormRange{Type: rng.Type, Introduced: introduced, LastAffected: e.LastAffected})
					introduced = ""
				}
			}
			if introduced != "" { // open range: introduced with no terminating event
				na.Ranges = append(na.Ranges, NormRange{Type: rng.Type, Introduced: introduced})
			}
		}
		adv.Affected = append(adv.Affected, na)
	}
	for _, ref := range r.References {
		adv.References = append(adv.References, NormReference{Kind: ref.Type, URL: ref.URL})
	}
	return adv
}

func sourceFromID(id string) string {
	if i := strings.IndexByte(id, '-'); i > 0 {
		return strings.ToLower(id[:i]) // GHSA, PYSEC, GO, RUSTSEC, CVE...
	}
	return "osv"
}

// severityLabel prefers the OSV database_specific qualitative severity, mapping
// GHSA's MODERATE to the internal "medium" vocabulary.
func (r *Record) severityLabel() string {
	raw, _ := r.DatabaseSpecific["severity"].(string)
	switch strings.ToUpper(raw) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MODERATE", "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	}
	return ""
}

// cvssVector returns the first CVSS vector string, preferring v4 over v3.
func (r *Record) cvssVector() string {
	var v3 string
	for _, s := range r.Severity {
		if !strings.HasPrefix(s.Score, "CVSS:") {
			continue
		}
		if strings.HasPrefix(s.Score, "CVSS:4") {
			return s.Score
		}
		if v3 == "" {
			v3 = s.Score
		}
	}
	return v3
}

func jsonString(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

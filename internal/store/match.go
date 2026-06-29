package store

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/bmsandoval/vigil/internal/osv"
)

// Instance is a resolved package present in a repo, joined with the context the
// matcher needs.
type Instance struct {
	InstanceID   int64
	RepoID       int64
	RepoName     string
	RepoMinSev   string
	Ecosystem    string
	PackageName  string
	Version      string
	IsDirect     bool
	Locator      string
	ManifestKind string
}

// AllInstances returns every package instance in enabled repos, optionally
// restricted to the given repo ids.
func (s *Store) AllInstances(repoIDs []int64) ([]Instance, error) {
	q := `
		SELECT pi.id, r.id, r.name, COALESCE(r.min_severity,''), p.ecosystem, p.name,
		       pi.version, pi.is_direct, COALESCE(pi.source_locator,''), m.kind
		FROM package_instances pi
		JOIN manifests m ON m.id = pi.manifest_id
		JOIN repositories r ON r.id = m.repo_id
		JOIN packages p ON p.id = pi.package_id
		WHERE r.enabled = 1`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	allow := map[int64]bool{}
	for _, id := range repoIDs {
		allow[id] = true
	}
	var out []Instance
	for rows.Next() {
		var in Instance
		var direct int
		if err := rows.Scan(&in.InstanceID, &in.RepoID, &in.RepoName, &in.RepoMinSev,
			&in.Ecosystem, &in.PackageName, &in.Version, &direct, &in.Locator, &in.ManifestKind); err != nil {
			return nil, err
		}
		in.IsDirect = direct == 1
		if len(allow) == 0 || allow[in.RepoID] {
			out = append(out, in)
		}
	}
	return out, rows.Err()
}

// AffectedAdvisory is an advisory's affected block for one package, with the
// data needed to evaluate a version and propose a remediation.
type AffectedAdvisory struct {
	AdvisoryID    string
	SeverityLabel string
	CVSSScore     float64
	Summary       string
	Withdrawn     bool
	AffectedVers  []string
	FixedVers     []string
	Ranges        []osv.NormRange
	Aliases       []string // CVE/GHSA cross-references, for alias dedup
}

// AffectedAdvisoriesFor returns advisories whose affected blocks name the given
// (ecosystem, package). This is the indexed equality join at the core of
// matching — never a fuzzy CPE lookup.
func (s *Store) AffectedAdvisoriesFor(ecosystem, name string) ([]AffectedAdvisory, error) {
	rows, err := s.db.Query(`
		SELECT aa.id, a.id, COALESCE(a.severity_label,''), COALESCE(a.cvss_score,0),
		       COALESCE(a.summary,''), a.withdrawn_at,
		       COALESCE(aa.affected_versions,''), COALESCE(aa.fixed_versions,'')
		FROM advisory_affected aa
		JOIN advisories a ON a.id = aa.advisory_id
		WHERE aa.ecosystem = ? AND aa.package_name = ?`, ecosystem, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type pending struct {
		affectedID int64
		adv        AffectedAdvisory
	}
	var items []pending
	for rows.Next() {
		var affectedID int64
		var adv AffectedAdvisory
		var withdrawn sql.NullString
		var affJSON, fixedJSON string
		if err := rows.Scan(&affectedID, &adv.AdvisoryID, &adv.SeverityLabel, &adv.CVSSScore,
			&adv.Summary, &withdrawn, &affJSON, &fixedJSON); err != nil {
			return nil, err
		}
		adv.Withdrawn = withdrawn.Valid && withdrawn.String != ""
		adv.AffectedVers = parseJSONArray(affJSON)
		adv.FixedVers = parseJSONArray(fixedJSON)
		items = append(items, pending{affectedID, adv})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]AffectedAdvisory, 0, len(items))
	for _, it := range items {
		ranges, err := s.rangesFor(it.affectedID)
		if err != nil {
			return nil, err
		}
		it.adv.Ranges = ranges
		aliases, err := s.aliasesFor(it.adv.AdvisoryID)
		if err != nil {
			return nil, err
		}
		it.adv.Aliases = aliases
		out = append(out, it.adv)
	}
	return out, nil
}

func (s *Store) aliasesFor(advisoryID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT alias FROM advisory_aliases WHERE advisory_id = ?`, advisoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) rangesFor(affectedID int64) ([]osv.NormRange, error) {
	rows, err := s.db.Query(`
		SELECT range_type, COALESCE(introduced,''), COALESCE(fixed,''), COALESCE(last_affected,'')
		FROM advisory_ranges WHERE affected_id = ?`, affectedID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []osv.NormRange
	for rows.Next() {
		var r osv.NormRange
		if err := rows.Scan(&r.Type, &r.Introduced, &r.Fixed, &r.LastAffected); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// IsExploited reports whether any of an advisory's aliases is in CISA KEV.
func (s *Store) IsExploited(advisoryID string) (bool, error) {
	var one int
	err := s.db.QueryRow(`
		SELECT 1 FROM advisory_aliases al
		JOIN exploitation e ON e.cve = al.alias
		WHERE al.advisory_id = ? AND e.in_kev = 1 LIMIT 1`, advisoryID).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// FixLinks returns fix/commit/advisory URLs for an advisory, for remediation.
func (s *Store) FixLinks(advisoryID string) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT url FROM references_links
		WHERE advisory_id = ? AND kind IN ('FIX','COMMIT','ADVISORY')
		ORDER BY CASE kind WHEN 'FIX' THEN 0 WHEN 'COMMIT' THEN 1 ELSE 2 END`, advisoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ── Scans & findings ────────────────────────────────────────────────────────

// CreateScan opens a new scan row and returns its id.
func (s *Store) CreateScan() (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO scans(started_at) VALUES(?)`, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishScan records completion counts.
func (s *Store) FinishScan(scanID int64, repoCount, findingCount int) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`UPDATE scans SET finished_at=?, repo_count=?, finding_count=? WHERE id=?`,
		now, repoCount, findingCount, scanID)
	return err
}

// Finding is a matcher result to persist.
type Finding struct {
	Fingerprint   string
	RepoID        int64
	InstanceID    int64
	AdvisoryID    string
	Severity      string
	Confidence    string
	IsTransitive  bool
	Exploited     bool
	FixedVersion  string
	LatestVersion string
	Rationale     string
}

// FindingDelta describes how a finding changed relative to its stored value.
type FindingDelta struct {
	IsNew          bool
	SeverityUp     bool
	NewlyExploited bool
}

// UpsertFinding inserts or refreshes a finding by fingerprint, reporting how it
// changed (new / severity increased / newly exploited) to drive notifications.
func (s *Store) UpsertFinding(scanID int64, f Finding) (FindingDelta, error) {
	var delta FindingDelta
	var prevSeverity string
	var prevExploited int
	row := s.db.QueryRow(`SELECT severity, exploited FROM findings WHERE fingerprint = ?`, f.Fingerprint)
	switch err := row.Scan(&prevSeverity, &prevExploited); err {
	case nil:
		delta.SeverityUp = severityRankInt(f.Severity) > severityRankInt(prevSeverity)
		delta.NewlyExploited = f.Exploited && prevExploited == 0
	case sql.ErrNoRows:
		delta.IsNew = true
		delta.NewlyExploited = f.Exploited
	default:
		return delta, err
	}

	_, err := s.db.Exec(`
		INSERT INTO findings(repo_id, package_instance_id, advisory_id, fingerprint,
			severity, confidence, is_transitive, exploited, fixed_version, latest_version,
			first_seen_scan, last_seen_scan, status, rationale)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
		ON CONFLICT(fingerprint) DO UPDATE SET
			package_instance_id=excluded.package_instance_id,
			severity=excluded.severity, confidence=excluded.confidence,
			is_transitive=excluded.is_transitive, exploited=excluded.exploited,
			fixed_version=excluded.fixed_version, latest_version=excluded.latest_version,
			last_seen_scan=excluded.last_seen_scan, status='open', rationale=excluded.rationale`,
		f.RepoID, f.InstanceID, f.AdvisoryID, f.Fingerprint,
		f.Severity, f.Confidence, boolToInt(f.IsTransitive), boolToInt(f.Exploited),
		nullStr(f.FixedVersion), nullStr(f.LatestVersion), scanID, scanID, nullStr(f.Rationale))
	if err != nil {
		return delta, err
	}
	return delta, nil
}

// AlreadyNotified reports whether an event for this finding has been sent on a
// given channel — the dedup guard so a finding alerts at most once per channel
// per event type.
func (s *Store) AlreadyNotified(fingerprint, channel, eventType string) (bool, error) {
	var one int
	err := s.db.QueryRow(`
		SELECT 1 FROM notifications_log
		WHERE finding_fingerprint = ? AND channel = ? AND event_type = ? LIMIT 1`,
		fingerprint, channel, eventType).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// RecordNotification logs that an event was dispatched on a channel.
func (s *Store) RecordNotification(fingerprint, channel, eventType string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`INSERT INTO notifications_log(finding_fingerprint, channel, event_type, sent_at) VALUES(?, ?, ?, ?)`,
		fingerprint, channel, eventType, now)
	return err
}

// ResolveStale marks open findings not seen in the given scan as resolved, and
// returns how many were closed.
func (s *Store) ResolveStale(scanID int64) (int, error) {
	res, err := s.db.Exec(
		`UPDATE findings SET status='resolved' WHERE status='open' AND last_seen_scan < ?`, scanID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// FindingView is an open finding joined with display context and any user
// decision (state).
type FindingView struct {
	Fingerprint   string
	RepoName      string
	Ecosystem     string
	PackageName   string
	Version       string
	Severity      string
	Confidence    string
	IsTransitive  bool
	Exploited     bool
	FixedVersion  string
	LatestVersion string
	AdvisoryID    string
	Rationale     string
	State         string // "" = active; acknowledged/dismissed/remediating/wont_fix
	StateNote     string
}

// Suppressed reports whether a finding is hidden from default reports.
func (v FindingView) Suppressed() bool {
	return v.State == StateDismissed || v.State == StateWontFix
}

// OpenFindings returns all open findings (with any user state) and the context
// needed to display them.
func (s *Store) OpenFindings() ([]FindingView, error) {
	rows, err := s.db.Query(`
		SELECT f.fingerprint, r.name, p.ecosystem, p.name, pi.version,
		       f.severity, f.confidence, f.is_transitive, f.exploited,
		       COALESCE(f.fixed_version,''), COALESCE(f.latest_version,''),
		       f.advisory_id, COALESCE(f.rationale,''),
		       COALESCE(st.state,''), COALESCE(st.note,'')
		FROM findings f
		JOIN repositories r ON r.id = f.repo_id
		JOIN package_instances pi ON pi.id = f.package_instance_id
		JOIN packages p ON p.id = pi.package_id
		LEFT JOIN finding_state st ON st.finding_fingerprint = f.fingerprint
		WHERE f.status = 'open'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingView
	for rows.Next() {
		var v FindingView
		var transitive, exploited int
		if err := rows.Scan(&v.Fingerprint, &v.RepoName, &v.Ecosystem, &v.PackageName, &v.Version,
			&v.Severity, &v.Confidence, &transitive, &exploited,
			&v.FixedVersion, &v.LatestVersion, &v.AdvisoryID, &v.Rationale,
			&v.State, &v.StateNote); err != nil {
			return nil, err
		}
		v.IsTransitive = transitive == 1
		v.Exploited = exploited == 1
		out = append(out, v)
	}
	return out, rows.Err()
}

func parseJSONArray(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

// severityRankInt mirrors the config severity ordering for stored labels.
func severityRankInt(s string) int {
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

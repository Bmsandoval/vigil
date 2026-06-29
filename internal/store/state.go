package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Finding-state values (VEX-aligned). dismissed/wont_fix suppress a finding
// from default reports; acknowledged/remediating keep it visible but flagged.
const (
	StateAcknowledged = "acknowledged"
	StateDismissed    = "dismissed"
	StateRemediating  = "remediating"
	StateWontFix      = "wont_fix"
)

// SetFindingState records a user decision for a finding, keyed by fingerprint so
// it survives across scans (and even if the finding is temporarily resolved).
func (s *Store) SetFindingState(fingerprint, state, justification, note, setBy string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
		INSERT INTO finding_state(finding_fingerprint, state, vex_justification, note, set_by, set_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(finding_fingerprint) DO UPDATE SET
			state=excluded.state, vex_justification=excluded.vex_justification,
			note=excluded.note, set_by=excluded.set_by, set_at=excluded.set_at`,
		fingerprint, state, nullStr(justification), nullStr(note), nullStr(setBy), now)
	return err
}

// ClearFindingState removes any decision for a finding (re-activates it).
func (s *Store) ClearFindingState(fingerprint string) error {
	_, err := s.db.Exec(`DELETE FROM finding_state WHERE finding_fingerprint = ?`, fingerprint)
	return err
}

// ResolveFingerprint expands a short fingerprint prefix to a full fingerprint,
// erroring if it matches zero or multiple findings.
func (s *Store) ResolveFingerprint(prefix string) (string, error) {
	rows, err := s.db.Query(
		`SELECT fingerprint FROM findings WHERE fingerprint LIKE ? LIMIT 2`, prefix+"%")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var matches []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return "", err
		}
		matches = append(matches, fp)
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no finding matches id %q", prefix)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("id %q is ambiguous — use more characters", prefix)
	}
}

// FindingSummary is a one-line description used to confirm state changes.
type FindingSummary struct {
	Fingerprint string
	PackageName string
	Version     string
	AdvisoryID  string
	Severity    string
}

// LookupFinding returns a short summary of a finding by full fingerprint.
func (s *Store) LookupFinding(fingerprint string) (FindingSummary, error) {
	var fs FindingSummary
	err := s.db.QueryRow(`
		SELECT f.fingerprint, p.name, pi.version, f.advisory_id, f.severity
		FROM findings f
		JOIN package_instances pi ON pi.id = f.package_instance_id
		JOIN packages p ON p.id = pi.package_id
		WHERE f.fingerprint = ?`, fingerprint).Scan(
		&fs.Fingerprint, &fs.PackageName, &fs.Version, &fs.AdvisoryID, &fs.Severity)
	if err == sql.ErrNoRows {
		return fs, fmt.Errorf("finding %q not found", fingerprint)
	}
	return fs, err
}

// SuppressedCount returns how many open findings are dismissed or wont_fix.
func (s *Store) SuppressedCount() (int, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM findings f
		JOIN finding_state st ON st.finding_fingerprint = f.fingerprint
		WHERE f.status='open' AND st.state IN ('dismissed','wont_fix')`).Scan(&n)
	return n, err
}

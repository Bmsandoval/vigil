package store

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/bmsandoval/vigil/internal/osv"
)

// UpsertAdvisory writes an advisory and its aliases, affected blocks, ranges,
// and references. It returns changed=true when the advisory is new or its
// content hash differs from what is stored (a revised advisory), so callers can
// detect severity/fix changes. Unchanged advisories are skipped cheaply.
func (s *Store) UpsertAdvisory(adv osv.Advisory) (changed bool, err error) {
	var existing string
	row := s.db.QueryRow(`SELECT content_hash FROM advisories WHERE id = ?`, adv.ID)
	switch err := row.Scan(&existing); err {
	case nil:
		if existing == adv.ContentHash {
			return false, nil
		}
	case sql.ErrNoRows:
	default:
		return false, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		INSERT INTO advisories(id, source, summary, details, severity_label,
			cvss_vector, cvss_score, published_at, modified_at, withdrawn_at,
			content_hash, raw_json)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			source=excluded.source, summary=excluded.summary, details=excluded.details,
			severity_label=excluded.severity_label, cvss_vector=excluded.cvss_vector,
			cvss_score=excluded.cvss_score, published_at=excluded.published_at,
			modified_at=excluded.modified_at, withdrawn_at=excluded.withdrawn_at,
			content_hash=excluded.content_hash, raw_json=excluded.raw_json`,
		adv.ID, adv.Source, nullStr(adv.Summary), nullStr(adv.Details),
		nullStr(adv.SeverityLabel), nullStr(adv.CVSSVector), nullFloat(adv.CVSSScore),
		nullStr(adv.Published), nullStr(adv.Modified), nullStr(adv.Withdrawn),
		adv.ContentHash, nullStr(adv.RawJSON)); err != nil {
		return false, err
	}

	// Replace child rows wholesale — simplest correct semantics on revision.
	for _, q := range []string{
		`DELETE FROM advisory_aliases WHERE advisory_id = ?`,
		`DELETE FROM references_links WHERE advisory_id = ?`,
	} {
		if _, err := tx.Exec(q, adv.ID); err != nil {
			return false, err
		}
	}
	// advisory_ranges cascade from advisory_affected, so delete affected first.
	if _, err := tx.Exec(`DELETE FROM advisory_affected WHERE advisory_id = ?`, adv.ID); err != nil {
		return false, err
	}

	for _, alias := range adv.Aliases {
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO advisory_aliases(advisory_id, alias) VALUES(?, ?)`,
			adv.ID, alias); err != nil {
			return false, err
		}
	}
	for _, ref := range adv.References {
		if _, err := tx.Exec(
			`INSERT INTO references_links(advisory_id, kind, url) VALUES(?, ?, ?)`,
			adv.ID, nullStr(ref.Kind), ref.URL); err != nil {
			return false, err
		}
	}
	for _, aff := range adv.Affected {
		res, err := tx.Exec(`
			INSERT INTO advisory_affected(advisory_id, ecosystem, package_name,
				affected_versions, fixed_versions, database_specific)
			VALUES(?, ?, ?, ?, ?, ?)`,
			adv.ID, aff.Ecosystem, aff.PackageName,
			nullStr(jsonArray(aff.Versions)), nullStr(jsonArray(aff.FixedVersions)),
			nullStr(aff.DatabaseSpecific))
		if err != nil {
			return false, err
		}
		affectedID, err := res.LastInsertId()
		if err != nil {
			return false, err
		}
		for _, rng := range aff.Ranges {
			if _, err := tx.Exec(`
				INSERT INTO advisory_ranges(affected_id, range_type, introduced, fixed, last_affected)
				VALUES(?, ?, ?, ?, ?)`,
				affectedID, rng.Type, nullStr(rng.Introduced),
				nullStr(rng.Fixed), nullStr(rng.LastAffected)); err != nil {
				return false, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// UpsertExploitation records a CISA KEV entry (CVE-keyed).
func (s *Store) UpsertExploitation(cve, dateAdded string, ransomware bool, dueDate string) error {
	_, err := s.db.Exec(`
		INSERT INTO exploitation(cve, in_kev, kev_date_added, ransomware, due_date)
		VALUES(?, 1, ?, ?, ?)
		ON CONFLICT(cve) DO UPDATE SET
			in_kev=1, kev_date_added=excluded.kev_date_added,
			ransomware=excluded.ransomware, due_date=excluded.due_date`,
		cve, nullStr(dateAdded), boolToInt(ransomware), nullStr(dueDate))
	return err
}

// GetCursor returns the stored cursor (ETag/timestamp) for a source key.
func (s *Store) GetCursor(source string) (string, error) {
	var c sql.NullString
	err := s.db.QueryRow(`SELECT cursor FROM source_cursors WHERE source = ?`, source).Scan(&c)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return c.String, err
}

// SetCursor records the cursor and sync time for a source key.
func (s *Store) SetCursor(source, cursor string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
		INSERT INTO source_cursors(source, cursor, last_sync_at) VALUES(?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor, last_sync_at=excluded.last_sync_at`,
		source, nullStr(cursor), now)
	return err
}

// CountAdvisories returns the number of stored advisories.
func (s *Store) CountAdvisories() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM advisories`).Scan(&n)
	return n, err
}

// DistinctEcosystems returns the ecosystems present in the current inventory,
// used to drive "auto" OSV sync (only download feeds for what we actually have).
func (s *Store) DistinctEcosystems() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT ecosystem FROM packages ORDER BY ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullFloat(f float64) any {
	if f == 0 {
		return nil
	}
	return f
}

func jsonArray(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	b, err := json.Marshal(xs)
	if err != nil {
		return ""
	}
	return string(b)
}

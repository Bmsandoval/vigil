package store

import (
	"database/sql"
	"time"

	"github.com/bmsandoval/vigil/internal/inventory"
)

// UpsertRepository inserts or updates a repository row and returns its id.
func (s *Store) UpsertRepository(name, path, source, minSeverity string) (int64, error) {
	_, err := s.db.Exec(`
		INSERT INTO repositories(name, path, source, min_severity)
		VALUES(?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET
			name = excluded.name,
			source = excluded.source,
			min_severity = excluded.min_severity`,
		name, path, source, nullStr(minSeverity))
	if err != nil {
		return 0, err
	}
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM repositories WHERE path = ?`, path).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// SaveManifest writes a manifest and its package instances for a repo. It
// returns changed=false (and skips rewriting instances) when an existing
// manifest has the same content hash, so unchanged files are cheap to re-scan.
func (s *Store) SaveManifest(repoID int64, m inventory.Manifest) (changed bool, err error) {
	var existingHash string
	row := s.db.QueryRow(
		`SELECT content_hash FROM manifests WHERE repo_id = ? AND file_path = ?`,
		repoID, m.RelPath)
	switch err := row.Scan(&existingHash); err {
	case nil:
		if existingHash == m.ContentHash {
			return false, nil
		}
	case sql.ErrNoRows:
		// new manifest
	default:
		return false, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := tx.Exec(`
		INSERT INTO manifests(repo_id, ecosystem, file_path, kind, content_hash, parsed_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(repo_id, file_path) DO UPDATE SET
			ecosystem = excluded.ecosystem,
			kind = excluded.kind,
			content_hash = excluded.content_hash,
			parsed_at = excluded.parsed_at,
			last_matched_db_version = ''`, // content changed → force re-match
		repoID, m.Ecosystem, m.RelPath, string(m.Kind), m.ContentHash, now)
	if err != nil {
		return false, err
	}
	manifestID, err := manifestIDFor(tx, res, repoID, m.RelPath)
	if err != nil {
		return false, err
	}

	// Replace instances wholesale — simplest correct semantics on content change.
	if _, err := tx.Exec(`DELETE FROM package_instances WHERE manifest_id = ?`, manifestID); err != nil {
		return false, err
	}
	for _, p := range m.Packages {
		pkgID, err := upsertPackage(tx, p.Ecosystem, p.Name, purlType(p.Purl))
		if err != nil {
			return false, err
		}
		if _, err := tx.Exec(`
			INSERT INTO package_instances(manifest_id, package_id, version, is_direct, purl, source_locator)
			VALUES(?, ?, ?, ?, ?, ?)
			ON CONFLICT(manifest_id, package_id, version) DO UPDATE SET
				is_direct = excluded.is_direct,
				purl = excluded.purl,
				source_locator = excluded.source_locator`,
			manifestID, pkgID, p.Version, boolToInt(p.Direct), nullStr(p.Purl), nullStr(p.Locator)); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func manifestIDFor(tx *sql.Tx, res sql.Result, repoID int64, relPath string) (int64, error) {
	if id, err := res.LastInsertId(); err == nil && id > 0 {
		// On an upsert, LastInsertId may reflect the conflicting row; verify by lookup.
		var got int64
		if err := tx.QueryRow(
			`SELECT id FROM manifests WHERE repo_id = ? AND file_path = ?`,
			repoID, relPath).Scan(&got); err == nil {
			return got, nil
		}
		return id, nil
	}
	var id int64
	err := tx.QueryRow(
		`SELECT id FROM manifests WHERE repo_id = ? AND file_path = ?`,
		repoID, relPath).Scan(&id)
	return id, err
}

func upsertPackage(tx *sql.Tx, ecosystem, name, purlType string) (int64, error) {
	if _, err := tx.Exec(`
		INSERT INTO packages(ecosystem, name, purl_type) VALUES(?, ?, ?)
		ON CONFLICT(ecosystem, name) DO UPDATE SET purl_type = excluded.purl_type`,
		ecosystem, name, nullStr(purlType)); err != nil {
		return 0, err
	}
	var id int64
	err := tx.QueryRow(`SELECT id FROM packages WHERE ecosystem = ? AND name = ?`,
		ecosystem, name).Scan(&id)
	return id, err
}

// CountInstancesForRepo returns how many package instances are recorded for a repo.
func (s *Store) CountInstancesForRepo(repoID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM package_instances pi
		JOIN manifests m ON m.id = pi.manifest_id
		WHERE m.repo_id = ?`, repoID).Scan(&n)
	return n, err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// purlType extracts the type from a purl ("pkg:golang/..." -> "golang").
func purlType(purl string) string {
	const prefix = "pkg:"
	if len(purl) <= len(prefix) || purl[:len(prefix)] != prefix {
		return ""
	}
	rest := purl[len(prefix):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[:i]
		}
	}
	return ""
}

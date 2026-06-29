package store

import (
	"path/filepath"
	"testing"
)

func TestOpenMigratesAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vigil.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Core tables should exist.
	for _, table := range []string{
		"repositories", "manifests", "packages", "package_instances",
		"advisories", "advisory_ranges", "exploitation", "findings",
		"finding_state", "source_cursors", "schema_migrations",
	} {
		var name string
		err := st.DB().QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Errorf("expected table %q to exist: %v", table, err)
		}
	}

	// Foreign keys must be enforced (orphan insert should fail).
	_, err = st.DB().Exec(`INSERT INTO manifests(repo_id, ecosystem, file_path, kind, content_hash)
		VALUES (999, 'Go', 'go.sum', 'lockfile', 'x')`)
	if err == nil {
		t.Error("expected foreign-key violation for orphan manifest")
	}
	st.Close()

	// Re-opening applies no new migrations and still works.
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer st2.Close()
	var n int
	if err := st2.DB().QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("expected 3 applied migrations, got %d", n)
	}
}

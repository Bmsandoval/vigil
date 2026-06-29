package store

import (
	"path/filepath"
	"testing"

	"github.com/bmsandoval/vigil/internal/inventory"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "vigil.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func sampleManifest(hash string) inventory.Manifest {
	return inventory.Manifest{
		Ecosystem:   "Go",
		RelPath:     "go.mod",
		Kind:        inventory.KindLockfile,
		ContentHash: hash,
		Packages: []inventory.Package{
			{Ecosystem: "Go", Name: "github.com/a/b", Version: "v1.0.0", Direct: true, Purl: "pkg:golang/github.com/a/b@v1.0.0", Locator: "go.mod:5"},
			{Ecosystem: "Go", Name: "github.com/c/d", Version: "v2.0.0", Direct: false, Purl: "pkg:golang/github.com/c/d@v2.0.0"},
		},
	}
}

func TestSaveManifestAndContentHashSkip(t *testing.T) {
	st := newTestStore(t)

	repoID, err := st.UpsertRepository("demo", "/tmp/demo", "service", "medium")
	if err != nil {
		t.Fatal(err)
	}

	changed, err := st.SaveManifest(repoID, sampleManifest("hash-v1"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("first save should report changed=true")
	}
	if n, _ := st.CountInstancesForRepo(repoID); n != 2 {
		t.Errorf("expected 2 instances, got %d", n)
	}

	// Same hash → skip, no rewrite, changed=false.
	changed, err = st.SaveManifest(repoID, sampleManifest("hash-v1"))
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("unchanged hash should report changed=false")
	}

	// New hash with fewer packages → replace instances wholesale.
	m := sampleManifest("hash-v2")
	m.Packages = m.Packages[:1]
	changed, err = st.SaveManifest(repoID, m)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("changed hash should report changed=true")
	}
	if n, _ := st.CountInstancesForRepo(repoID); n != 1 {
		t.Errorf("expected 1 instance after replace, got %d", n)
	}
}

func TestUpsertRepositoryIdempotent(t *testing.T) {
	st := newTestStore(t)
	id1, err := st.UpsertRepository("demo", "/tmp/demo", "service", "low")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := st.UpsertRepository("demo-renamed", "/tmp/demo", "service", "high")
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Errorf("same path should yield same repo id: %d vs %d", id1, id2)
	}
	var name, minSev string
	if err := st.DB().QueryRow(`SELECT name, min_severity FROM repositories WHERE id=?`, id1).Scan(&name, &minSev); err != nil {
		t.Fatal(err)
	}
	if name != "demo-renamed" || minSev != "high" {
		t.Errorf("upsert did not update fields: name=%q minSev=%q", name, minSev)
	}
}

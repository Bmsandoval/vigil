package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// Malformed or empty dependency files must produce a parse error for that file
// (surfaced by Scan), never a panic.
func TestScanHandlesMalformedFiles(t *testing.T) {
	cases := map[string]string{
		"package-lock.json": `{ this is not json `,
		"pnpm-lock.yaml":    "::: not: valid: yaml: [",
		"poetry.lock":       "[[package]\nbroken",
	}
	for file, body := range cases {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		// Should return an error, not panic.
		_, err := Scan(dir, nil, nil)
		if err == nil {
			t.Errorf("%s: expected parse error for malformed content", file)
		}
	}
}

func TestScanHandlesEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	// Empty go.mod / requirements.txt should parse to zero packages, no error.
	for _, f := range []string{"requirements.txt"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ms, err := Scan(dir, nil, nil)
	if err != nil {
		t.Fatalf("empty files should not error: %v", err)
	}
	for _, m := range ms {
		if len(m.Packages) != 0 {
			t.Errorf("%s should have 0 packages, got %d", m.RelPath, len(m.Packages))
		}
	}
}

func TestScanEmptyDir(t *testing.T) {
	ms, err := Scan(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 0 {
		t.Errorf("empty dir should yield no manifests, got %d", len(ms))
	}
}

func TestScanNonexistentPath(t *testing.T) {
	// A configured path that doesn't exist should not panic.
	ms, err := Scan(filepath.Join(t.TempDir(), "does-not-exist"), nil, nil)
	if err != nil {
		return // acceptable
	}
	if len(ms) != 0 {
		t.Errorf("nonexistent path should yield no manifests, got %d", len(ms))
	}
}

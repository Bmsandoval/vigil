package ingest

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/bmsandoval/vigil/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "vigil.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func makeZip(t *testing.T, records map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range records {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const advJSON = `{
  "id": "GHSA-xxxx",
  "summary": "demo",
  "aliases": ["CVE-2024-2222"],
  "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "affected": [{"package":{"ecosystem":"npm","name":"lodash"},
    "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}],
  "database_specific": {"severity":"HIGH"}
}`

func TestRefreshOSVAndKEVWithETag(t *testing.T) {
	st := newStore(t)
	zipBytes := makeZip(t, map[string]string{"lodash/GHSA-xxxx.json": advJSON, "README": "ignore me"})

	const etag = `"v1"`
	var osvHits, condHits int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/npm/all.zip":
			osvHits++
			if r.Header.Get("If-None-Match") == etag {
				condHits++
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			w.Write(zipBytes)
		case "/kev.json":
			w.Write([]byte(`{"vulnerabilities":[
				{"cveID":"CVE-2024-2222","dateAdded":"2024-03-01","dueDate":"2024-03-21","knownRansomwareCampaignUse":"Known"},
				{"cveID":"","dateAdded":"x"}
			]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := &Refresher{
		Store:      st,
		HTTP:       srv.Client(),
		OSVBaseURL: srv.URL,
		KEVURL:     srv.URL + "/kev.json",
	}

	// First refresh: downloads zip, ingests advisory + KEV.
	res := r.Refresh([]string{"npm"}, true)
	if len(res.OSV) != 1 || res.OSV[0].Err != nil {
		t.Fatalf("osv result: %+v", res.OSV)
	}
	if res.OSV[0].Total != 1 || res.OSV[0].Changed != 1 {
		t.Errorf("expected 1 advisory (1 changed), got %+v", res.OSV[0])
	}
	if res.KEVCount != 1 || res.KEVErr != nil { // empty cveID skipped
		t.Errorf("kev count = %d, err = %v", res.KEVCount, res.KEVErr)
	}
	if n, _ := st.CountAdvisories(); n != 1 {
		t.Errorf("advisories stored = %d", n)
	}

	// Second refresh: ETag should produce a 304 and no re-ingest.
	res2 := r.Refresh([]string{"npm"}, false)
	if !res2.OSV[0].NotModified {
		t.Errorf("expected NotModified on second refresh, got %+v", res2.OSV[0])
	}
	if condHits != 1 {
		t.Errorf("expected 1 conditional 304, got %d (osvHits=%d)", condHits, osvHits)
	}

	// Verify the advisory landed with computed CVSS and resolvable KEV join.
	var score float64
	st.DB().QueryRow(`SELECT cvss_score FROM advisories WHERE id='GHSA-xxxx'`).Scan(&score)
	if score < 9.0 {
		t.Errorf("expected critical CVSS score, got %.1f", score)
	}
	var inKev int
	st.DB().QueryRow(`SELECT in_kev FROM exploitation WHERE cve='CVE-2024-2222'`).Scan(&inKev)
	if inKev != 1 {
		t.Error("KEV entry not stored")
	}
}

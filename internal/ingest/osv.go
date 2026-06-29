package ingest

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/bmsandoval/vigil/internal/osv"
)

// syncOSVEcosystem downloads <base>/<ecosystem>/all.zip (ETag-gated) and upserts
// every advisory it contains. A 304 Not Modified short-circuits the work.
func (r *Refresher) syncOSVEcosystem(ecosystem string) EcoResult {
	res := EcoResult{Ecosystem: ecosystem}
	cursorKey := "osv:" + ecosystem

	etag, err := r.Store.GetCursor(cursorKey)
	if err != nil {
		res.Err = err
		return res
	}

	zipURL := r.osvBase() + "/" + url.PathEscape(ecosystem) + "/all.zip"
	req, err := http.NewRequest(http.MethodGet, zipURL, nil)
	if err != nil {
		res.Err = err
		return res
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := r.httpClient().Do(req)
	if err != nil {
		res.Err = err
		return res
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		res.NotModified = true
		return res
	case http.StatusOK:
		// proceed
	default:
		res.Err = fmt.Errorf("osv %s: unexpected status %s", ecosystem, resp.Status)
		return res
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		res.Err = err
		return res
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		res.Err = fmt.Errorf("osv %s: open zip: %w", ecosystem, err)
		return res
	}

	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		data, err := readZipEntry(f)
		if err != nil {
			continue // skip a single bad entry rather than failing the feed
		}
		rec, err := osv.ParseRecord(data)
		if err != nil || rec.ID == "" {
			continue
		}
		adv := rec.Normalize(data)
		changed, err := r.Store.UpsertAdvisory(adv)
		if err != nil {
			res.Err = fmt.Errorf("osv %s: upsert %s: %w", ecosystem, rec.ID, err)
			return res
		}
		res.Total++
		if changed {
			res.Changed++
		}
	}

	// Persist the new ETag only after a fully successful ingest.
	if err := r.Store.SetCursor(cursorKey, resp.Header.Get("ETag")); err != nil {
		res.Err = err
	}
	r.log(fmt.Sprintf("osv %s: %d advisories (%d new/changed)", ecosystem, res.Total, res.Changed))
	return res
}

func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

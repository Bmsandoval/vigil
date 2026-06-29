// Package ingest syncs public advisory feeds into the local store. It is the
// only part of Vigil that touches the network, and only during a refresh.
//
// Sources are ETag/cursor-gated so repeated refreshes are cheap, and each
// advisory is content-hashed so revisions (severity bumps, new fixes) are
// detected. HTTP client and base URLs are injectable so the pipeline is fully
// testable without the real network.
package ingest

import (
	"net/http"
	"time"

	"github.com/bmsandoval/vigil/internal/store"
)

const (
	// DefaultOSVBaseURL is the public OSV per-ecosystem ZIP bucket.
	DefaultOSVBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"
	// DefaultKEVURL is the CISA Known Exploited Vulnerabilities feed.
	DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// Refresher orchestrates advisory ingestion.
type Refresher struct {
	Store      *store.Store
	HTTP       *http.Client
	OSVBaseURL string
	KEVURL     string
	Log        func(string) // optional progress sink
}

// EcoResult summarizes one ecosystem's OSV sync.
type EcoResult struct {
	Ecosystem   string
	Total       int  // advisories seen in the feed
	Changed     int  // new or revised
	NotModified bool // server returned 304 — nothing fetched
	Err         error
}

// Result is the outcome of a full refresh.
type Result struct {
	OSV      []EcoResult
	KEVCount int
	KEVErr   error
}

func (r *Refresher) httpClient() *http.Client {
	if r.HTTP != nil {
		return r.HTTP
	}
	return &http.Client{Timeout: 120 * time.Second}
}

func (r *Refresher) osvBase() string {
	if r.OSVBaseURL != "" {
		return r.OSVBaseURL
	}
	return DefaultOSVBaseURL
}

func (r *Refresher) kevURL() string {
	if r.KEVURL != "" {
		return r.KEVURL
	}
	return DefaultKEVURL
}

func (r *Refresher) log(msg string) {
	if r.Log != nil {
		r.Log(msg)
	}
}

// Refresh syncs the given OSV ecosystems and, when syncKEV is true, the KEV
// feed. Errors on individual ecosystems are captured per-result rather than
// aborting the whole refresh.
func (r *Refresher) Refresh(ecosystems []string, syncKEV bool) Result {
	var res Result
	for _, eco := range ecosystems {
		er := r.syncOSVEcosystem(eco)
		res.OSV = append(res.OSV, er)
	}
	if syncKEV {
		res.KEVCount, res.KEVErr = r.syncKEV()
	}
	return res
}

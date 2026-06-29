package ingest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// kevFeed is the subset of the CISA KEV JSON we consume.
type kevFeed struct {
	Vulnerabilities []struct {
		CveID                      string `json:"cveID"`
		DateAdded                  string `json:"dateAdded"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// syncKEV downloads the CISA Known Exploited Vulnerabilities feed and upserts
// each entry. The feed is small and unconditional (no ETag gating needed).
func (r *Refresher) syncKEV() (int, error) {
	resp, err := r.httpClient().Get(r.kevURL())
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("kev: unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	var feed kevFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return 0, fmt.Errorf("kev: parse: %w", err)
	}

	count := 0
	for _, v := range feed.Vulnerabilities {
		if v.CveID == "" {
			continue
		}
		ransomware := strings.EqualFold(v.KnownRansomwareCampaignUse, "Known")
		if err := r.Store.UpsertExploitation(v.CveID, v.DateAdded, ransomware, v.DueDate); err != nil {
			return count, fmt.Errorf("kev: upsert %s: %w", v.CveID, err)
		}
		count++
	}
	if err := r.Store.SetCursor("kev", ""); err != nil {
		return count, err
	}
	r.log(fmt.Sprintf("kev: %d exploited CVEs", count))
	return count, nil
}

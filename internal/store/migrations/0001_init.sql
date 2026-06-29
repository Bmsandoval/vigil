-- Vigil initial schema. See docs/DESIGN.md §4.
-- Applied as a single transaction by the migration runner.

-- ── Repositories & inventory ───────────────────────────────
CREATE TABLE repositories (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    path            TEXT NOT NULL UNIQUE,
    source          TEXT NOT NULL DEFAULT 'service',  -- 'service' | 'discover'
    vcs_remote      TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    min_severity    TEXT,                             -- effective floor at enroll time
    last_scanned_at TEXT
);

CREATE TABLE manifests (
    id           INTEGER PRIMARY KEY,
    repo_id      INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ecosystem    TEXT NOT NULL,                       -- 'npm','Go','PyPI',...
    file_path    TEXT NOT NULL,                       -- relative to repo
    kind         TEXT NOT NULL,                       -- 'lockfile'|'manifest'|'sbom'
    content_hash TEXT NOT NULL,
    parsed_at    TEXT,
    UNIQUE(repo_id, file_path)
);

CREATE TABLE packages (
    id        INTEGER PRIMARY KEY,
    ecosystem TEXT NOT NULL,
    name      TEXT NOT NULL,
    purl_type TEXT,
    UNIQUE(ecosystem, name)
);

CREATE TABLE package_instances (
    id             INTEGER PRIMARY KEY,
    manifest_id    INTEGER NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
    package_id     INTEGER NOT NULL REFERENCES packages(id),
    version        TEXT NOT NULL,
    is_direct      INTEGER NOT NULL DEFAULT 0,
    purl           TEXT,
    source_locator TEXT,                              -- file:line of the declaration
    UNIQUE(manifest_id, package_id, version)
);

CREATE TABLE dependency_edges (
    id                 INTEGER PRIMARY KEY,
    manifest_id        INTEGER NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
    parent_instance_id INTEGER NOT NULL REFERENCES package_instances(id) ON DELETE CASCADE,
    child_instance_id  INTEGER NOT NULL REFERENCES package_instances(id) ON DELETE CASCADE
);

-- ── Advisories ─────────────────────────────────────────────
CREATE TABLE advisories (
    id             TEXT PRIMARY KEY,                  -- OSV/GHSA id (canonical)
    source         TEXT NOT NULL,                     -- 'osv','ghsa','nvd'
    summary        TEXT,
    details        TEXT,
    severity_label TEXT,                              -- CRITICAL/HIGH/...
    cvss_vector    TEXT,
    cvss_score     REAL,
    published_at   TEXT,
    modified_at    TEXT,
    withdrawn_at   TEXT,
    content_hash   TEXT NOT NULL,                     -- drives "changed" detection
    raw_json       TEXT
);

CREATE TABLE advisory_aliases (
    advisory_id TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    alias       TEXT NOT NULL,                        -- e.g. 'CVE-2024-1234'
    PRIMARY KEY(advisory_id, alias)
);
CREATE INDEX idx_alias ON advisory_aliases(alias);

CREATE TABLE advisory_affected (
    id                INTEGER PRIMARY KEY,
    advisory_id       TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    ecosystem         TEXT NOT NULL,
    package_name      TEXT NOT NULL,
    affected_versions TEXT,                           -- JSON array of explicit versions
    fixed_versions    TEXT,                           -- JSON array
    database_specific TEXT
);
CREATE INDEX idx_affected_pkg ON advisory_affected(ecosystem, package_name);

CREATE TABLE advisory_ranges (
    id            INTEGER PRIMARY KEY,
    affected_id   INTEGER NOT NULL REFERENCES advisory_affected(id) ON DELETE CASCADE,
    range_type    TEXT NOT NULL,                      -- 'SEMVER','ECOSYSTEM','GIT'
    introduced    TEXT,                               -- '0' = from beginning
    fixed         TEXT,
    last_affected TEXT
);

CREATE TABLE exploitation (
    cve            TEXT PRIMARY KEY,                  -- KEV is CVE-keyed
    in_kev         INTEGER NOT NULL DEFAULT 1,
    kev_date_added TEXT,
    ransomware     INTEGER NOT NULL DEFAULT 0,
    due_date       TEXT
);

CREATE TABLE references_links (
    advisory_id TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    kind        TEXT,                                 -- 'ADVISORY','FIX','COMMIT','WEB','REPORT'
    url         TEXT NOT NULL
);
CREATE INDEX idx_reflinks_adv ON references_links(advisory_id);

-- ── Scan history & findings ────────────────────────────────
CREATE TABLE scans (
    id                  INTEGER PRIMARY KEY,
    started_at          TEXT NOT NULL,
    finished_at         TEXT,
    repo_count          INTEGER NOT NULL DEFAULT 0,
    finding_count       INTEGER NOT NULL DEFAULT 0,
    advisory_db_version TEXT
);

CREATE TABLE findings (
    id                  INTEGER PRIMARY KEY,
    repo_id             INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    -- SET NULL (not CASCADE): when an upgrade replaces a package instance, the
    -- finding must survive so the next scan can mark it resolved.
    package_instance_id INTEGER REFERENCES package_instances(id) ON DELETE SET NULL,
    advisory_id         TEXT NOT NULL REFERENCES advisories(id),
    fingerprint         TEXT NOT NULL UNIQUE,         -- hash(repo,pkg,version,advisory)
    severity            TEXT NOT NULL,
    confidence          TEXT NOT NULL,                -- Confirmed/Probable/Possible/NotAffected
    is_transitive       INTEGER NOT NULL DEFAULT 0,
    exploited           INTEGER NOT NULL DEFAULT 0,
    fixed_version       TEXT,
    latest_version      TEXT,
    first_seen_scan     INTEGER REFERENCES scans(id),
    last_seen_scan      INTEGER REFERENCES scans(id),
    status              TEXT NOT NULL DEFAULT 'open',  -- 'open' | 'resolved'
    rationale           TEXT
);
CREATE INDEX idx_findings_open ON findings(status, severity);
CREATE INDEX idx_findings_repo ON findings(repo_id);

-- User decisions, keyed by fingerprint so they survive re-scans. VEX-aligned.
CREATE TABLE finding_state (
    finding_fingerprint TEXT PRIMARY KEY,
    state               TEXT NOT NULL,                -- acknowledged|dismissed|remediating|wont_fix
    vex_justification   TEXT,
    note                TEXT,
    set_by              TEXT,
    set_at              TEXT NOT NULL
);

CREATE TABLE notifications_log (
    id                  INTEGER PRIMARY KEY,
    finding_fingerprint TEXT,
    channel             TEXT NOT NULL,
    event_type          TEXT NOT NULL,                -- new|severity_up|kev|newly_affected_repo
    sent_at             TEXT NOT NULL
);
CREATE INDEX idx_notif_fp ON notifications_log(finding_fingerprint);

-- Per-source ingestion cursors (ETag/last-modified/timestamp) for incremental refresh.
CREATE TABLE source_cursors (
    source       TEXT PRIMARY KEY,                    -- 'osv:Go','kev','nvd'
    cursor       TEXT,
    last_sync_at TEXT
);

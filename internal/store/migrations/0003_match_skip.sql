-- Incremental match: remember the advisory-DB version a manifest was last
-- matched against. A re-scan can skip matching a manifest whose content hash is
-- unchanged AND whose last_matched_db_version equals the current advisory-DB
-- version — nothing could have changed the result. Cleared on content change.
ALTER TABLE manifests ADD COLUMN last_matched_db_version TEXT NOT NULL DEFAULT '';

-- Monotonic revision counter bumped whenever an advisory or KEV entry actually
-- changes. This is the "advisory-DB version": a manifest matched at revision N
-- can be safely skipped while the counter is still N.
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO meta(key, value) VALUES ('mirror_revision', '0');

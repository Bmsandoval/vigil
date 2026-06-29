-- Reachability dimension from govulncheck (Go): 'called' (affected symbol is
-- reachable), 'imported' (present but not called), '' / 'unknown' (not analyzed).
ALTER TABLE findings ADD COLUMN reachability TEXT NOT NULL DEFAULT '';

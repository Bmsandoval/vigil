package version

// InRange reports whether v falls within a single OSV affected range, defined
// by an introduced bound and either a fixed (exclusive upper) or last_affected
// (inclusive upper) bound. An empty or "0" introduced means "from the
// beginning". An error is returned if a needed comparison fails to parse.
func InRange(c Comparator, v, introduced, fixed, lastAffected string) (bool, error) {
	if introduced != "" && introduced != "0" {
		cmp, err := c.Compare(v, introduced)
		if err != nil {
			return false, err
		}
		if cmp < 0 { // below the introduced bound
			return false, nil
		}
	}
	if fixed != "" {
		cmp, err := c.Compare(v, fixed)
		if err != nil {
			return false, err
		}
		if cmp >= 0 { // at or above the fix → not affected
			return false, nil
		}
	}
	if lastAffected != "" {
		cmp, err := c.Compare(v, lastAffected)
		if err != nil {
			return false, err
		}
		if cmp > 0 { // beyond the last affected version
			return false, nil
		}
	}
	return true, nil
}

// MinFixedAbove returns the smallest fixed version strictly greater than
// current (the minimal safe upgrade) and the greatest fixed version (the latest
// known fix). Versions that don't parse are skipped. Returns empty strings when
// no usable fixed version is available.
func MinFixedAbove(c Comparator, current string, fixed []string) (minSafe, latest string) {
	for _, f := range fixed {
		if f == "" || !c.Valid(f) {
			continue
		}
		if latest == "" {
			latest = f
		} else if cmp, err := c.Compare(f, latest); err == nil && cmp > 0 {
			latest = f
		}
		if cmp, err := c.Compare(f, current); err == nil && cmp > 0 {
			if minSafe == "" {
				minSafe = f
			} else if c2, err := c.Compare(f, minSafe); err == nil && c2 < 0 {
				minSafe = f
			}
		}
	}
	return minSafe, latest
}

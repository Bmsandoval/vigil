// Package reachability runs govulncheck over a Go module and reports which
// vulnerabilities are actually reachable (their affected symbols are called)
// versus merely present. This is the strongest false-positive control Vigil
// has: a vulnerability in an imported-but-unreachable code path can be
// confidently downgraded.
//
// govulncheck and the Go toolchain are only invoked when the user opts in; the
// JSON parsing and cross-referencing are pure and fully testable via an
// injectable runner.
package reachability

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Level is how deeply govulncheck determined a vulnerability reaches.
type Level int

const (
	// LevelUnknown means govulncheck did not analyze this vulnerability.
	LevelUnknown Level = iota
	// LevelImported: the vulnerable package is imported but no affected symbol
	// is called — typically NOT exploitable.
	LevelImported
	// LevelCalled: an affected symbol is reachable — genuinely exploitable.
	LevelCalled
)

func (l Level) String() string {
	switch l {
	case LevelCalled:
		return "called"
	case LevelImported:
		return "imported"
	default:
		return "unknown"
	}
}

// Report maps each analyzed vulnerability id (and its aliases) to a Level.
type Report struct {
	// byID is keyed by every known identifier for a vuln (the GO- id and each
	// alias), so a Vigil finding can be looked up by advisory id or CVE alias.
	byID map[string]Level
	// Ran indicates govulncheck completed; if false, no downgrades are applied.
	Ran bool
}

// Lookup returns the reachability level for any of the given identifiers
// (advisory id + aliases), taking the most severe known level.
func (r *Report) Lookup(ids ...string) Level {
	best := LevelUnknown
	for _, id := range ids {
		if lvl, ok := r.byID[id]; ok && lvl > best {
			best = lvl
		}
	}
	return best
}

// Runner executes govulncheck and returns its JSON output stream. It is
// injectable so tests can supply canned output.
type Runner func(ctx context.Context, dir string) (io.Reader, error)

// Available reports whether govulncheck is on PATH.
func Available() bool {
	_, err := exec.LookPath("govulncheck")
	return err == nil
}

// ExecRunner runs the real govulncheck in source (call-graph) mode.
func ExecRunner(ctx context.Context, dir string) (io.Reader, error) {
	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = dir
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		// govulncheck exits non-zero when vulns are found; that's not an error
		// for us as long as we got parseable JSON.
		if out.Len() == 0 {
			return nil, fmt.Errorf("govulncheck: %v: %s", err, strings.TrimSpace(errBuf.String()))
		}
	}
	return &out, nil
}

// Analyze runs the given runner over dir and parses the result into a Report.
func Analyze(ctx context.Context, dir string, run Runner) (*Report, error) {
	r, err := run(ctx, dir)
	if err != nil {
		return &Report{byID: map[string]Level{}}, err
	}
	return Parse(r)
}

// govulncheck -json emits a stream of objects, each with exactly one of these
// top-level keys.
type message struct {
	OSV     *osvEntry `json:"osv"`
	Finding *finding  `json:"finding"`
}

type osvEntry struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

type finding struct {
	OSV   string  `json:"osv"`
	Trace []frame `json:"trace"`
}

type frame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

// Parse reads a govulncheck JSON stream into a Report.
func Parse(r io.Reader) (*Report, error) {
	rep := &Report{byID: map[string]Level{}, Ran: true}
	aliases := map[string][]string{} // osv id → aliases

	dec := json.NewDecoder(bufio.NewReader(r))
	for {
		var m message
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			return rep, fmt.Errorf("parse govulncheck json: %w", err)
		}
		switch {
		case m.OSV != nil:
			aliases[m.OSV.ID] = m.OSV.Aliases
		case m.Finding != nil:
			level := levelOf(m.Finding)
			if cur := rep.byID[m.Finding.OSV]; level > cur {
				rep.byID[m.Finding.OSV] = level
			}
		}
	}

	// Propagate each vuln's level to all of its aliases so Vigil findings can be
	// matched by CVE/GHSA id as well as the GO- id.
	for id, lvl := range cloneLevels(rep.byID) {
		for _, alias := range aliases[id] {
			if rep.byID[alias] < lvl {
				rep.byID[alias] = lvl
			}
		}
	}
	return rep, nil
}

// levelOf classifies a finding: a trace whose most specific frame names a
// function means an affected symbol is called (reachable).
func levelOf(f *finding) Level {
	if len(f.Trace) == 0 {
		return LevelImported
	}
	if f.Trace[0].Function != "" {
		return LevelCalled
	}
	return LevelImported
}

func cloneLevels(m map[string]Level) map[string]Level {
	out := make(map[string]Level, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

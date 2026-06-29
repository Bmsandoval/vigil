// Command vigil is a local-first vulnerability intelligence CLI.
//
// It watches local repositories on disk, mirrors public advisory data
// (OSV/KEV/NVD) into a local SQLite store, and reports whether any
// newly-disclosed vulnerability actually affects code you have checked out —
// favoring correctness and low false positives over reporting lots of CVEs.
//
// This is the MVP skeleton: commands are wired but their logic is stubbed.
// See docs/DESIGN.md and docs/ROADMAP.md for the full plan.
package main

import "github.com/bmsandoval/vigil/internal/cmd"

func main() {
	cmd.Execute()
}

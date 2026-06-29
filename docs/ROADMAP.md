# Vigil — Roadmap

Incremental milestones. Each milestone is independently useful and testable. See
[DESIGN.md](DESIGN.md) for the architecture the milestones build toward.

Principle: **all real logic lives in `internal/` packages** with no CLI/TUI coupling,
so the eventual desktop app is additive (see DESIGN §10).

---

## Current state

Skeleton only. `vigil --help` works; every command prints a "not yet implemented"
stub pointing at its milestone. Standard Cobra + `internal/cmd/` structure.

```
vigil/
  cmd/vigil/main.go          # thin entry → cmd.Execute()
  internal/cmd/*.go          # cobra commands (init, service, refresh, scan, status)
  config.example.toml        # documented config (source of truth)
  docs/{DESIGN,ROADMAP}.md
  Makefile                   # make run / make setup (+ build/test/tidy)
```

---

## MVP

Goal: end-to-end value for Go/npm/Python — offline-capable, low false positives.

### M0 — Skeleton & store ✅ DONE
- [x] Go module, Cobra scaffold, `vigil --help`, Makefile (`run`/`setup`).
- [x] `internal/store`: SQLite open (WAL, FKs), embedded migration runner
      (`schema_migrations`), full schema from DESIGN §4. Tested (FK enforcement,
      idempotent re-open).
- [x] `internal/config`: load `config.toml`, unknown-key rejection, env-ref
      resolution (`env:NAME`), `~` expansion, override cascade (service → global),
      required-secret validation. Tested.
- [x] `vigil init` writes starter config + creates DB. `vigil service add/list`
      edit/read config (dedup + dir validation, append preserves comments).
      `vigil status` reports services + mirror age + open findings.
- [x] `--config` flag / `$VIGIL_CONFIG` override.

### M1 — Inventory (Go, npm/pnpm, Python) ✅ DONE
- [x] `internal/discover`: resolve services + discover-roots (git-dir walk, depth
      limit, excludes) into a deduped repo list.
- [x] `internal/inventory`: parser registry + `Scan` (default skip-dirs, ecosystem
      filter, content hashing). Parsers: Go (`go.mod` via x/mod/modfile, indirect
      detection), npm (`package-lock.json` v2/v3 + v1 fallback, scoped/nested
      names), pnpm (`pnpm-lock.yaml` v6/v9, peer-suffix strip), Python
      (`requirements.txt` pinned + `poetry.lock` with pyproject direct cross-ref).
      Produces `package_instances` with direct/transitive, purl, source_locator.
- [x] `internal/store`: `UpsertRepository`, `SaveManifest` (content-hash skip,
      wholesale instance replace on change), `packages` upsert.
- [x] `vigil scan` wired to inventory + persist + report (matching deferred to M3).
- [x] Tested: 8 inventory parser tests + 3 store persistence tests; e2e multi-
      ecosystem scan verified.

### M2 — Advisory mirror ✅ DONE
- [x] `internal/osv`: OSV schema model + `Normalize` (range events → introduced/
      fixed/last_affected rows, fixed-version collection, alias/reference
      flattening, content hashing) + CVSS v3.0/3.1 base-score parser with
      qualitative-label fallback.
- [x] `internal/ingest`: `Refresher` orchestrator with injectable HTTP/URLs.
      OSV bulk ZIP download (ETag-gated, 304 short-circuit) + KEV JSON sync.
- [x] `internal/store`: `UpsertAdvisory` (content-hash change detection,
      wholesale child-row replace), `UpsertExploitation`, cursor get/set,
      `DistinctEcosystems` for "auto" mode.
- [x] `vigil refresh` (`--source osv,kev`); fully offline thereafter.
- [x] Tested: OSV/CVSS unit tests (incl. 3 CVSS reference vectors), store
      advisory/exploitation tests, httptest-driven OSV+KEV ingest with ETag/304.
      Live smoke: 1629 KEV CVEs + 2556 crates.io advisories, 304 re-sync verified.

### M3 — Match engine ✅ DONE
- [x] `internal/version`: `Comparator` interface + registry. SemVer (Masterminds,
      for npm/crates.io/Packagist/Pub/Hex/NuGet), Go (x/mod/semver, v-prefix
      normalization), PEP 440 (PyPI, epoch/pre/post/dev ordering). `InRange` +
      `MinFixedAbove` (minimal-safe / latest fix).
- [x] `internal/match`: candidate selection by (ecosystem, name), range eval,
      severity × confidence classification (confirmed/probable/possible, withdrawn
      skipped), KEV join, rationale + remediation, stable fingerprints.
- [x] `internal/store`: inventory/advisory join queries, `findings` upsert with
      new + severity-up detection, `ResolveStale` scan diff, `OpenFindings` view.
- [x] FK fix: `findings.package_instance_id` is `ON DELETE SET NULL` so findings
      survive instance churn and can be resolved (caught by a diff test).
- [x] `vigil scan` wired: inventory → match → priority-sorted report
      (exploited > severity > confidence > direct), `--min-severity` filter.
- [x] Tested: version/range/PEP-440 unit tests, match engine tests (affected vs
      safe, KEV, resolve-on-upgrade, withdrawn, severity-change). Live e2e: 7988
      Go advisories, correctly flagged jwt-go v3.2.0+incompatible (high), cobra clean.

> Future polish (not blocking): dedup findings that are CVE aliases of each other
> (e.g. GHSA + GO-/PYSEC for the same CVE currently both appear).

### M4 — Output & state ✅ DONE
- [x] `internal/report`: markdown generator — grouped by repo, priority-ordered,
      with rationale, remediation, osv.dev + reference links; suppressed findings
      summarized not detailed.
- [x] `internal/store`: `finding_state` methods (set/clear, VEX justification),
      `ResolveFingerprint` (short-id prefix → full, ambiguity-checked),
      `LookupFinding`, `SuppressedCount`; `OpenFindings` now LEFT JOINs state.
- [x] `vigil findings` (list w/ short ids, `--all`, `--min-severity`),
      `vigil ack` / `vigil dismiss` (`--wont-fix`, `--justification`, `--note`) /
      `vigil reset` → `finding_state`, survives rescans. Dismissed hidden from
      default report.
- [x] `vigil report` (stdout or `--out`); scan auto-writes `vigil-report.md` when
      `notify.markdown` is enabled. `vigil status` shows dismissed count.
- [x] Tested: store state lifecycle + fingerprint resolution + lookup, report
      rendering (grouping/priority/suppression/links). Live e2e: dismiss persists
      and hides; markdown report written with rationale + links.

### M5 — Daemon & notifications ✅ DONE
- [x] `internal/scanner`: shared inventory→match pipeline (used by `scan`, `watch`,
      and any future UI).
- [x] `internal/match`: emits `Event`s (new / severity_up / newly_exploited);
      `UpsertFinding` returns a `FindingDelta`.
- [x] `internal/notify`: `Dispatcher` with per-channel dedup via
      `notifications_log`; channels = terminal, webhook (Slack/Discord, injectable
      client), desktop (osascript/notify-send, injectable notifier). OR-semantics
      severity/exploited filter.
- [x] `vigil watch`: signal-aware daemon — periodic refresh + scan (ticker) or
      `on-change` via `fsnotify` (debounced); `--once` for a single cycle.
- [x] Tested: dispatcher dedup + severity/exploited filtering, webhook (httptest),
      injectable desktop notifier, scanner pipeline events. Live e2e: `watch --once`
      refreshed 7988 advisories, alerted (terminal+webhook, filtered), 2nd cycle
      deduped to 0.

**MVP exit:** ✅ point Vigil at your repos → confirmed-affected findings with fixes
→ dismissals stick → KEV hits stand out → re-running offline works → daemon alerts
once per finding. **All MVP milestones (M0–M5) complete.**

---

## Phase 2

- [ ] Remaining ecosystems: Cargo, Maven/Gradle, Terraform, Composer/Ruby.
- [ ] **Go reachability** via govulncheck (symbol-level → "Not affected (unreachable)").
- [ ] NVD CVSS enrichment; native RustSec/PyPA git mirrors for freshness.
- [ ] SBOM ingestion (CycloneDX/SPDX) + generation (Syft) output.
- [ ] Container image scanning (shell out to Grype/Trivy).
- [ ] Email/Slack/Discord polish; daily digest; severity-change UI.
- [ ] VEX export of `finding_state`.
- [ ] **Remote GitHub tracking** (`[[github]]` config block):
      - `mode = "manifest"` first — fetch lockfiles via Contents API, reuse parsers.
      - then `dependency-graph` (GitHub SBOM API), then `clone`.
      - optional Dependabot cross-check (agreement → higher confidence).
- [ ] **Claude-assisted triage** (subprocess + stream-json pattern):
      explain "does this matter to you" per finding, read-only/opt-in.

---

## Phase 3 / Future ideas

Documented, not committed: auto-PRs / Dependabot-style upgrades; GitHub Issues / Jira
ticket creation; patch verification (rescan-after-upgrade); CI gate integration;
secret scanning; **malicious-package / typosquatting / install-script detection**
(own ingestion source — worth a dedicated design); license compliance (SPDX).

---

## Desktop graduation (tracked, not scheduled)

Keep `internal/` packages CLI-agnostic from M0 so the GUI is a new frontend, not a
rewrite. Intermediate: Bubble Tea TUI. Shell decision (Wails/Fyne native vs
Tauri/Electron over a local daemon) deferred — see DESIGN §10.

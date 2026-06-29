# Vigil — Engineering Design

> Local-first vulnerability intelligence for a developer workstation. Not a SIEM,
> SOC, or cloud product. It runs entirely on your machine and watches your local
> source repositories. It determines whether newly-disclosed security issues
> actually affect your codebases, favoring **correctness and low false positives**
> over reporting lots of CVEs.

Status: **design + skeleton**. Commands are wired (`vigil --help` works); logic is
stubbed. See [ROADMAP.md](ROADMAP.md) for sequencing.

---

## 1. Executive Summary

Vigil is a **single Go binary** (CLI today, desktop app later) that watches local
git repositories, mirrors public advisory data into SQLite, and reports whether a
newly-disclosed vulnerability actually affects code you have on disk — with a clear
"why" and an upgrade/mitigation.

Core decisions:

1. **OSV.dev is the matching backbone.** It is the only source that natively
   expresses vulnerabilities as machine-readable, ecosystem-aware version ranges,
   aggregates GHSA + ecosystem feeds, is free, and ships a downloadable full
   database for offline matching. NVD/KEV/CVE are enrichment layers.
2. **Matching is driven by lockfiles, not SBOM generation or manifests.** Lockfiles
   carry the package manager's fully-resolved, transitively-pinned versions — the
   ground truth of "what is actually present." Manifests are version *ranges* (too
   loose); SBOM generation just re-derives the lockfile. SBOM **ingestion** is an
   optional alternate input; SBOM **generation** is a later output feature.
3. **Storage is SQLite** (one file, offline-capable, transactional). Network access
   happens only during `refresh`.
4. **Severity and Confidence are orthogonal.** Severity (how bad) comes from the
   advisory; Confidence (how sure it affects *you*) comes from how cleanly we
   resolved the package, version, and reachability. This separation is the main
   false-positive control.
5. **Reachability is out of MVP but designed for.** Version-range matching ships
   first; Go call-graph reachability (govulncheck-style) is the first major
   correctness upgrade because the Go vuln DB carries affected symbols.

**Reuse:** the CLI scaffold follows a standard Cobra + `internal/cmd/` layout. The
optional "explain a finding with a local Claude session" feature uses a subprocess +
`stream-json` parsing + secret-isolation pattern.

---

## 2. Vulnerability Intelligence Sources

| Source | Provides | Freq | License | Limits | Verdict |
|---|---|---|---|---|---|
| **OSV.dev** | Ecosystem-aware affected version ranges (OSV schema); aggregates GHSA/PyPA/RustSec/Go/npm/etc. | Continuous | CC-BY / Apache | No key; bulk ZIP per ecosystem (offline) | **PRIMARY / matcher** |
| **GHSA** | Human-curated ranges, severity, fix links; OSV-format git repo | Continuous | CC-BY-4.0 | git clone or GraphQL PAT | Useful (arrives via OSV) |
| **NVD** | Canonical CVSS, CWE, CPE | Continuous (analysis lag) | Public domain | 5/30s (50 with key); CPE is poor for libs | Enrichment (CVSS only) |
| **CISA KEV** | Confirmed in-the-wild exploitation; ransomware flag | Irregular, low volume | Public domain | one JSON file | **Must-have prioritization signal** |
| **CVE / CVE.org 5.x** | Canonical CVE IDs/records | Continuous | CC0 | git `cvelistV5` | Identity/alias join key |
| **Go vuln DB** | OSV + **affected symbols** | Continuous | BSD | `vuln.go.dev` | High value — enables reachability |
| **RustSec / PyPA / rubysec** | Ecosystem OSV exports | Continuous | per-repo | git | Via OSV in MVP; native later for freshness |
| **RSS / mailing lists** | Earliest human signal, unstructured | Continuous | varies | noisy | Awareness-only, never auto-matched |

SBOM/scanners: **OSV-Scanner** (Go, Apache-2.0) is the closest existing tool and a
reuse/shell-out candidate for lockfile parsers + version comparators. **Grype/Trivy**
are the later container-image path. **CycloneDX VEX** is the right model for our
ack/dismiss state. **SPDX** is for license compliance (future). SBOM **generation**
via Syft is a Phase 2 output.

**Strategy:** OSV (download + API) for matching → KEV for exploitation → NVD for CVSS
normalization → CVE IDs as the join key → native Go DB later for reachability.

---

## 3. Architecture

Local daemon + CLI, single Go binary, organized as decoupled components around a
SQLite store. Components talk only through the DB, so each is independently testable
and schedulable.

```
                          ┌──────────────────────────────────────────────┐
                          │                 CLI / Daemon                   │
                          │   scan · refresh · status · ack · dismiss      │
                          └───────────────┬───────────────┬───────────────┘
        ┌─────────────────────────────────┘               └────────────────────┐
        ▼                                                                        ▼
┌───────────────────┐    ┌────────────────────┐    ┌──────────────────┐   ┌──────────────┐
│ Repo Discovery &  │    │ Advisory Ingestion │    │  Impact / Match  │   │ Notification │
│ Inventory         │    │ (OSV/KEV/NVD)      │    │  Engine          │   │ Dispatch     │
│ • walk repos      │    │ • bulk download    │    │ • inventory ×    │   │ • terminal   │
│ • detect manifests│    │ • incremental API  │    │   advisories     │   │ • markdown   │
│ • parse lockfiles │    │ • dedup / cursor   │    │ • range check    │   │ • desktop    │
│ • normalize purl  │    │ • normalize→OSV    │    │ • severity×conf  │   │ • email/slack│
└─────────┬─────────┘    └─────────┬──────────┘    └────────┬─────────┘   └──────┬───────┘
          └────────────────────────┴───────────┬────────────┴────────────────────┘
                                                ▼
                                    ┌───────────────────────┐
                                    │   SQLite store (WAL)   │
                                    └───────────────────────┘
```

### Data flow

**Refresh (networked, scheduled):** check per-source cursor → OSV bulk ZIPs
(ETag-gated) + KEV JSON + NVD CVSS for thin advisories → normalize to OSV model,
record aliases → mark processed (content hash) → emit "new/changed advisory" events.

**Scan (offline):** discover repos → parse lockfiles → for each package look up
advisories by (ecosystem, name) → evaluate version vs ranges → compute
severity×confidence + rationale + remediation → upsert findings → diff vs prior scan
→ apply ack/dismiss state → notify on the diff only.

The two flows are decoupled: a refresh can re-match against existing inventory; a
scan matches against the existing mirror. Both write `findings`.

---

## 4. SQLite Schema (conceptual)

Full DDL lives in code (M0). Key tables and why they matter:

- **repositories / manifests / packages / package_instances / dependency_edges** —
  the inventory. `package_instances` holds the *resolved pinned version* with
  `is_direct`, `purl`, and a `source_locator` (file:line) for actionability.
- **advisories / advisory_aliases / advisory_affected / advisory_ranges** — the
  mirror. Ranges store OSV `introduced`/`fixed`/`last_affected` events;
  `content_hash` drives "severity changed" detection; `raw_json` preserves
  provenance. `advisory_aliases` (CVE/GHSA) is the cross-source join.
- **exploitation** — KEV, CVE-keyed, joined via aliases.
- **references_links** — advisory / fix / commit URLs for remediation.
- **scans / findings** — `findings.fingerprint` = stable hash(repo,pkg,version,
  advisory) is the spine for dedup, scan-diffing, and persisting suppression.
  Stores `severity`, `confidence`, `exploited`, `fixed_version`, `latest_version`,
  and a generated `rationale`.
- **finding_state** — user actions (acknowledged/dismissed/remediating/wont_fix)
  keyed by fingerprint, **separate** from `findings` so re-scans never clobber
  decisions. Maps to **CycloneDX VEX** justifications for future export.
- **notifications_log** — dedup/throttle per channel + event type.

---

## 5. Repository Discovery & Inventory

**Decision: parse lockfiles primary; manifests fallback; ingest SBOMs optionally;
generate SBOMs never (MVP).** A lockfile is the package manager's resolved,
transitive, pinned answer — exact, no network, no build.

| Ecosystem | Primary lockfile | Direct vs transitive | Notes |
|---|---|---|---|
| Go | `go.sum`+`go.mod` (best: `go mod graph`) | `go.mod require` = direct | pseudo-versions; reachability later via govulncheck |
| npm | `package-lock.json` v2/v3 | `package.json` | full tree in lock |
| pnpm | `pnpm-lock.yaml` | importers section | richest JS graph |
| yarn | `yarn.lock` | `package.json` | resolve ranges→pinned |
| Python | `poetry.lock`/`Pipfile.lock`/`uv.lock`/pinned `requirements.txt` | tool-dependent | unpinned reqs → manifest mode |
| Cargo | `Cargo.lock` | `Cargo.toml` | clean SemVer; RustSec quality high |
| Maven | `pom.xml` + `mvn dependency:tree` | mgmt vs transitive | pom-only = manifest mode |
| Gradle | `gradle.lockfile` | `build.gradle` | else `gradle dependencies` (opt-in build) |
| Docker | Dockerfile base tags; later image SBOM | n/a | real scan = image layers (Phase 2) |
| Terraform | `.terraform.lock.hcl` | provider blocks | matches provider CVEs |

Edges: unpinned manifests → *manifest mode*, confidence capped at **Possibly
affected**; monorepos → each lockfile is its own manifest row; vendored deps covered
via lockfile. Optional **SBOM ingestion** (CycloneDX/SPDX) feeds the same pipeline
via purl.

---

## 6. Advisory Ingestion

**Bulk-first, incremental-after, dedup-always.**

1. **Seed (bulk):** download OSV per-ecosystem `all.zip` only for ecosystems present
   across watched repos → functional offline immediately.
2. **Incremental:** OSV ZIPs gated by ETag/Last-Modified (or API `querybatch` over
   present packages); KEV JSON every refresh (cheap); NVD only for CVE aliases of
   new/changed advisories lacking CVSS, with keyed backoff on 429.
3. **Dedup:** per-source cursor + per-advisory content hash → insert/update/no-op. A
   hash change on an advisory mapped to an open finding raises "severity changed."
4. **Normalize:** everything to the internal OSV-aligned model, joined by CVE alias.
5. **Offline:** no network ⇒ ingestion is a no-op; scans run against the last mirror,
   labeled with `advisory_db_version` / sync age.

`Source` interface: `Sync(ctx, cursor) -> (records, nextCursor, err)`. New sources
(RustSec mirror, Go DB, RSS awareness) drop in without touching the matcher.

---

## 7. Matching Algorithm (Impact Analysis)

High recall on real hits, aggressively suppressed false positives, explainable per
finding.

1. **Candidate selection:** indexed equality join on (ecosystem, name) with
   per-ecosystem name normalization (npm scopes, Go module paths, PEP-503). **Never
   CPE.**
2. **Version evaluation:** walk OSV range events into intervals; affected if the
   pinned version falls in any open interval or the explicit version list. Behind a
   `Comparator` interface per ecosystem (SemVer, Go semver/pseudo, PEP 440, Maven,
   RubyGems/NuGet/Composer). Heaviest fixture test suite lives here — reuse OSV's
   corpora.
3. **Severity:** CVSS (OSV→NVD) → else GHSA qualitative → else Informational. A
   property of the vuln, independent of confidence.
4. **Confidence** (FP control):
   - **Confirmed** — exact package + pinned lockfile version in range, not withdrawn.
   - **Probable** — in range but ambiguity (version quirk, git-range only).
   - **Possible** — manifest-mode (range, no pinned version).
   - **Not affected** — version outside ranges or advisory withdrawn (tracked, not
     notified). Future: govulncheck "unreachable symbol" → Not affected.
5. **Exploitation:** join aliases → KEV; a KEV hit sets `exploited` and outranks CVSS.
6. **Ranking:** `exploited DESC, severity DESC, confidence DESC, is_direct DESC,
   fix_available DESC`.
7. **Rationale:** generated per finding (package, path/transitive chain, advisory,
   affected range, fixed version, KEV status, confidence + why).
8. **Remediation:** minimal safe upgrade (smallest jump ≥ fixed), latest upgrade,
   breaking-change risk (SemVer delta + direct/transitive), mitigation if no upgrade
   (npm `overrides` / Go `replace` / pip constraints / Cargo `[patch]`), and
   advisory/fix/commit links.

**Optional Claude-assisted triage:** pass advisory + local code
context to a local `claude` session (`--output-format stream-json`, secrets kept out
of the subprocess env) to generate a human "does this matter to you" explanation.
Read-only, opt-in, never gates a finding.

---

## 8. Notifications

Event-sourced off the **scan diff**, not the full finding set (prevents fatigue). A
differ compares open findings by fingerprint vs the prior scan and emits typed
events: `new_finding`, `severity_up`, `newly_exploited`, `newly_affected_repo`
(`resolved` for digests). Suppression drops dismissed/wont_fix; acknowledged appears
in digests only.

Channels (pluggable sinks, each filterable by min-severity / exploited-only):
terminal (default), markdown report (shareable artifact), desktop (KEV/critical
live), email (SMTP digest), Slack/Discord (webhook). `notifications_log` dedups per
channel. **Default policy:** live push only for `newly_exploited` and critical
`new_finding`; everything else in the daily digest.

---

## 9. Technology Stack

| Concern | Choice | Why |
|---|---|---|
| Language | **Go 1.26** | single static binary, daemon+CLI, and the OSV/OSV-Scanner/govulncheck ecosystem is Go — reuse parsers & comparators |
| CLI | **spf13/cobra** | standard Go CLI scaffold |
| TUI → desktop bridge | Bubble Tea (later) | interactive views first, then graduate to a real GUI |
| Storage | SQLite WAL via `modernc.org/sqlite` (cgo-free) | keeps the single-binary promise |
| Lockfile parsing | reuse OSV-Scanner parsers | don't rewrite 10 ecosystems |
| Version compare | OSV semver libs | tested corpora |
| Scheduling | ticker + `fsnotify` | no external cron; also runs one-shot under user cron |
| Notifications | pluggable sinks (`beeep`, SMTP, webhooks) | all optional |
| Config | `config.toml` + SQLite DB | human-editable source of truth; machine-owned state |
| Optional engines | shell out to `osv-scanner`/`govulncheck`/`trivy` if present | deeper analysis without reimplementation |

The "reuse OSV-Scanner internals" choice collapses the riskiest correctness surface
onto a maintained codebase, leaving us to build the differentiated layer: persistent
history, dedup/fingerprinting, ack/dismiss state, enrichment, and notifications.

---

## 10. CLI → Desktop graduation

Build the CLI so the desktop app is additive, not a rewrite:

- **All logic lives in `internal/` packages** (discovery, ingest, match, store,
  notify) with no CLI/TUI coupling. `internal/cmd` and any future GUI are both thin
  frontends over the same packages.
- **The SQLite DB + `config.toml` are the only interface** to state — a desktop app
  reads the same DB the CLI writes.
- **A Bubble Tea TUI** is the intermediate step and validates the view models a GUI
  will need.
- Desktop shell options when we get there: a Go-native GUI (Wails/Fyne) reusing the
  same packages directly, or a thin Tauri/Electron front-end over a local `vigil`
  daemon exposing a localhost API. Decision deferred; the package boundaries above
  keep both open.

---

## 11. Risks & Tradeoffs

- **Version-comparator correctness** is the dominant risk → reuse OSV libs + fixtures;
  never hand-roll SemVer.
- **Manifest-mode ambiguity** → cap confidence, label it.
- **Transitive remediation is hard** → advise (overrides), don't auto-fix in MVP.
- **No reachability in MVP** → some Confirmed findings are present-but-unreachable;
  severity×confidence + Go reachability (Phase 2) mitigate.
- **Offline staleness** → always surface DB age; absence ≠ safe.
- **Reusing OSV-Scanner internals** couples us to its API; acceptable, and we can
  shell out instead if the surface churns.

---

## 12. Final Recommendation

Go single-binary local daemon, SQLite store, decoupled discovery/ingest/match/notify
components. OSV is the matching backbone (bulk + API), enriched by KEV (exploitation)
and NVD (CVSS), driven by **lockfiles** for exact versions. The defining choice is
**separating severity from confidence** and capping confidence honestly — that's what
delivers "low false positives, immediately actionable." Reuse OSV-Scanner parsers and
version libs; spend effort on the intelligence layer (history, fingerprinting,
VEX-aligned state, KEV/severity-change detection, diff-driven notifications). Ship MVP
across Go/npm/Python, then expand ecosystems and add Go reachability.

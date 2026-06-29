# Vigil

**Local-first vulnerability intelligence for your repositories.**

Vigil watches the git repositories you keep on disk, maintains a local mirror of
public vulnerability advisories (OSV, CISA KEV, NVD) in SQLite, and tells you — with
a clear rationale and low false positives — whether a newly-disclosed vulnerability
actually affects code you have checked out.

Not a SIEM, SOC, or cloud product. Everything runs on your machine. Network access
happens only while refreshing advisories; scans work fully offline.

> Status: **early skeleton.** Commands are wired (`vigil --help` works) but logic is
> stubbed. See [docs/DESIGN.md](docs/DESIGN.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## Quick start

```bash
make setup                 # install deps, scaffold config + store
# edit ~/.config/vigil/config.toml (see config.example.toml)
make run ARGS=refresh      # sync the advisory mirror (only networked step)
make run ARGS=scan         # inventory repos + report findings (offline)
make run ARGS=status
```

## Commands

| Command | Purpose |
|---|---|
| `vigil init` | scaffold `config.toml` + initialize the SQLite store |
| `vigil service add/list` | manage the on-disk repos Vigil watches |
| `vigil refresh` | sync the advisory mirror (OSV/KEV/NVD) — only networked command |
| `vigil scan` | inventory watched repos and report findings (offline) |
| `vigil status` | services, advisory-mirror age, open findings by severity |

## Design in one breath

OSV is the matching backbone; KEV adds exploitation, NVD adds CVSS. Matching is driven
by **lockfiles** (exact resolved versions), and every finding carries an orthogonal
**Severity × Confidence** score — the main control against false positives. Built as a
Go CLI today, structured so it can graduate into a desktop app without a rewrite.

See [docs/DESIGN.md](docs/DESIGN.md) for the full engineering design.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

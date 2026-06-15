# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-15

First public release. A single, dependency-light Go binary that gives an
installable agent skill a signed capability manifest and rejects any skill that
reaches for a capability it never declared.

### Added

- **m1 — capability manifest + SBOM (`skillsig manifest`)**
  Walk a skill directory, compute a per-file sha256 content lock, parse the
  declared capabilities from `SKILL.md` frontmatter, and emit a schema-valid
  `capability-manifest.json` plus a minimal CycloneDX 1.5-subset `sbom.cdx.json`.
  The command also prints a declared-vs-observed table so an author catches a
  missing declaration before they ship. Validated against
  `schema/capability-manifest.v0.schema.json`.
- **m2 — signed provenance bundle (`skillsig sign`)**
  Sign the canonical manifest with a local ed25519 key (auto-generated on first
  use, stored as PEM) and write a detached, self-describing `bundle.sig`. The
  signing path is fully offline. A manifest modified after signing fails the next
  verify.
- **m3 — declared-vs-observed verification (`skillsig verify`)**
  Recompute the content lock, validate the ed25519 signature, then statically
  re-scan the skill and diff observed capabilities (net / fs-write / exec / env)
  against the declared set. Any undeclared capability produces a red `REJECTED`
  verdict with file:line evidence and exit code 1, dropping straight into a CI
  gate or an install pre-hook.
- `testdata/clean-skill` and `testdata/poisoned-skill` so the
  `sign → verify (PASS) → verify (REJECTED)` loop is reproducible out of the box.
- Bilingual README (Chinese primary, English sibling), MIT license, and an
  asciinema demo cast.

[0.1.0]: https://github.com/SuperMarioYL/skillsig/releases/tag/v0.1.0

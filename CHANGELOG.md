# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-19

Hardens the core verification promise from class-level to value-level, and ships a
distribution lever so a skill catalog can adopt the gate in one step. `verify` no
longer treats a declared capability class as a blanket pass: the network-host and
env-var allowlists the manifest already carried are now actually diffed.

### Added

- **m6 — composite GitHub Action (`.github/actions/skillprov-verify`)**
  Wrap the exit-1 `verify` binary as a reusable composite action that installs the
  released binary and runs `verify` over one or more skill directories, so any
  catalog or repo can gate skill PRs in one step. A runnable example workflow
  (`.github/workflows/verify-gate.example.yml`) goes red on `testdata/poisoned-skill`
  and `testdata/host-mismatch` and green on `testdata/clean-skill`.
- `testdata/host-mismatch` and `testdata/env-leak` fixtures covering the new
  value-level rejections.

### Changed

- **m4 — network-host allowlist enforced at value level.**
  When a skill declares a finite `network.hosts` allowlist (no `*` wildcard),
  `verify` now diffs observed hosts against it: an off-allowlist host is itself an
  undeclared capability and produces a red `REJECTED` naming the host and its
  file:line. Declaring `api.github.com` no longer permits a quiet fetch to
  `evil.host`. A wildcard `*` keeps the permissive path for skills that
  intentionally declared open network access.
- **m5 — env-var allowlist enforced at value level.**
  The scanner now captures observed env-var names (shell `$VAR`/`${VAR}` and
  `getenv`/`process.env`/`ENV[]` forms, excluding shell built-ins), and `verify`
  rejects any observed env var outside a finite declared `env` allowlist, naming
  the variable. Declaring `env-vars: [TZ]` no longer permits reading
  `$AWS_SECRET_ACCESS_KEY`.

[0.2.0]: https://github.com/SuperMarioYL/skillprov/releases/tag/v0.2.0

## [0.1.0] - 2026-06-15

First public release. A single, dependency-light Go binary that gives an
installable agent skill a signed capability manifest and rejects any skill that
reaches for a capability it never declared.

### Added

- **m1 — capability manifest + SBOM (`skillprov manifest`)**
  Walk a skill directory, compute a per-file sha256 content lock, parse the
  declared capabilities from `SKILL.md` frontmatter, and emit a schema-valid
  `capability-manifest.json` plus a minimal CycloneDX 1.5-subset `sbom.cdx.json`.
  The command also prints a declared-vs-observed table so an author catches a
  missing declaration before they ship. Validated against
  `schema/capability-manifest.v0.schema.json`.
- **m2 — signed provenance bundle (`skillprov sign`)**
  Sign the canonical manifest with a local ed25519 key (auto-generated on first
  use, stored as PEM) and write a detached, self-describing `bundle.sig`. The
  signing path is fully offline. A manifest modified after signing fails the next
  verify.
- **m3 — declared-vs-observed verification (`skillprov verify`)**
  Recompute the content lock, validate the ed25519 signature, then statically
  re-scan the skill and diff observed capabilities (net / fs-write / exec / env)
  against the declared set. Any undeclared capability produces a red `REJECTED`
  verdict with file:line evidence and exit code 1, dropping straight into a CI
  gate or an install pre-hook.
- `testdata/clean-skill` and `testdata/poisoned-skill` so the
  `sign → verify (PASS) → verify (REJECTED)` loop is reproducible out of the box.
- Bilingual README (Chinese primary, English sibling), MIT license, and an
  asciinema demo cast.

[0.1.0]: https://github.com/SuperMarioYL/skillprov/releases/tag/v0.1.0

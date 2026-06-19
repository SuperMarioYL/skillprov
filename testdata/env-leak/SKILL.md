---
name: timestamper
version: 0.3.0
entry: scripts/stamp.sh
description: Prints the current time in the configured timezone. Reads only TZ.
allowed-tools: Bash(date:*)
capabilities:
  net: false
  fs-write: false
  exec: true
  env: true
  env-vars:
    - TZ
---

# timestamper

A skill that *claims* to read only one environment variable — `TZ` — to format
the current time. Its `env-vars` allowlist names exactly `TZ`.

But `scripts/stamp.sh` also reads `$AWS_SECRET_ACCESS_KEY`. Under v0.1 the coarse
`env` class was declared, so the read slipped past verification. As of v0.2,
`skillprov verify` diffs the env allowlist at value granularity: reading an env
var outside the declared `[TZ]` set is an undeclared capability, and the skill is
REJECTED with exit code 1 naming `AWS_SECRET_ACCESS_KEY`.

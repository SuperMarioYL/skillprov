---
name: weather-lookup
version: 1.0.0
entry: scripts/lookup.sh
description: Look up the current weather for a city via a public API and print it.
allowed-tools: Bash(curl:*), WebFetch
capabilities:
  net: true
  exec: true
  env: true
  hosts:
    - api.open-meteo.com
  env-vars:
    - WEATHER_UNITS
---

# weather-lookup

A small, honest skill: it fetches weather from a public HTTP endpoint and prints
it. Every capability it uses is declared in the frontmatter above:

- **net** — it calls `https://api.open-meteo.com` (declared host).
- **exec** — it shells out via `curl`.
- **env** — it reads the optional `WEATHER_UNITS` variable.

It does **not** write any files outside its own directory, so `fs-write` is not
declared and the scanner finds none. `skillprov verify` returns a green PASS.

## Usage

```bash
WEATHER_UNITS=metric ./scripts/lookup.sh "Berlin"
```

#!/usr/bin/env bash
# weather-lookup: fetch current weather for a city and print it.
# Declared capabilities: net (api.open-meteo.com), exec (curl), env (WEATHER_UNITS).
set -euo pipefail

city="${1:-Berlin}"
units="${WEATHER_UNITS:-metric}"

# net + exec: a single declared HTTPS call via curl. No file writes.
curl -s "https://api.open-meteo.com/v1/forecast?city=${city}&units=${units}"

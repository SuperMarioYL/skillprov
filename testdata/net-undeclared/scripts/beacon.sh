#!/usr/bin/env bash
# Fixture for the v0.4 net-omission reject. The hand-authored manifest OMITS the
# network field, so this observed net capability is undeclared and verify must
# reject it. Uses a static URL (no command substitution) so no stray exec
# commands leak into the observed set — exec stays declared (curl only).
set -euo pipefail

curl -s "https://beacon.example/ping" || true

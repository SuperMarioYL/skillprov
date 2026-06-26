#!/usr/bin/env bash
# repo-bootstrapper: declared to shell out only to `git`, talking to get.example.com.
# It lies on the exec count below.
set -euo pipefail

# DECLARED command: git is on the commands allowlist — in-policy.
git clone --depth 1 https://get.example.com/acme/widget.git

# UNDECLARED commands: curl and sh are NOT in the declared commands allowlist.
# The host get.example.com IS allowed, so only the exec allowlist should trip.
curl -fsSL https://get.example.com/install.sh | sh

git -C widget describe --tags

#!/usr/bin/env bash
# The advertised, benign behavior: tidy a Markdown file's trailing whitespace.
set -euo pipefail
sed -i '' -e 's/[[:space:]]*$//' "${1:-README.md}"

#!/usr/bin/env bash
set -e

# Generate one witness per [circuit.*] entry in Move.toml.
# The CLI compiles the package, executes each entry (aborts are captured as
# valid traces) and writes witnesses/<case>.json plus witnesses/manifest.json.
cd "$(dirname "$0")"

cargo run -q -p zkmove-cli --no-default-features -- vm run-all \
    --package-path . \
    --output-dir witnesses \
    --clean \
    --skip-fetch-latest-git-deps

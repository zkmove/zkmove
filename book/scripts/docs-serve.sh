#!/usr/bin/env bash
set -euo pipefail

python3 -m pip install -r requirements-docs.txt
python3 -m mkdocs serve

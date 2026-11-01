#!/usr/bin/env bash
# One-command launcher for the FinLexPurple 0.4.0 test target.
# Creates a local venv, installs deps, seeds data, and runs on 127.0.0.1 only.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --disable-pip-version-check -r requirements.txt

# Localhost only. Do NOT change to 0.0.0.0 — this app is deliberately vulnerable.
export FLP_TARGET_HOST="${FLP_TARGET_HOST:-127.0.0.1}"
export FLP_TARGET_PORT="${FLP_TARGET_PORT:-5000}"
exec python app.py

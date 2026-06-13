#!/usr/bin/env bash
#
# One-command, key-free, fully reproducible benchmark repro.
#
# Runs the deterministic `local` (synthetic/reference) provider over the
# committed reference config, writes a byte-stable result JSON, and regenerates
# the Markdown summary tables FROM that result data (never hand-written numbers).
#
# SYNTHETIC / REFERENCE ONLY: the verdicts produced here are deterministic
# fixtures, NOT measurements of any real model. See benchmarks/README.md.
#
# Usage:
#   scripts/run_local_benchmark.sh
#
# Re-running must produce an identical benchmarks/results/local-reference.json
# (verify with `git diff --exit-code benchmarks/results/`).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CONFIG="benchmarks/benchmark-local-reference.yaml"
RESULT_DIR="benchmarks/results"
RESULT_JSON="$RESULT_DIR/local-reference.json"
SUMMARY_MD="$RESULT_DIR/local-reference-summary.md"
RUN_ID="local-reference"

mkdir -p "$RESULT_DIR"

echo ">> Running deterministic (synthetic/reference) benchmark — no API keys required"
python "$REPO_ROOT/scripts/run_local_benchmark.py" \
  --config "$CONFIG" \
  --run-id "$RUN_ID" \
  --result-json "$RESULT_JSON" \
  --summary-md "$SUMMARY_MD"

echo ">> Wrote $RESULT_JSON and $SUMMARY_MD"
echo ">> To verify reproducibility: git diff --exit-code $RESULT_DIR"

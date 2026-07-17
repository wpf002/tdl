#!/usr/bin/env bash
# Fetch real Windows EVTX attack samples for the TDL lab.
#
# Uses EVTX-ATTACK-SAMPLES (sbousseaden) — hundreds of .evtx captures mapped to
# MITRE ATT&CK techniques, a perfect match for TDL's ATT&CK-mapped rules.
#
#   ./fetch_samples.sh              # shallow-clone the full sample set (~a few hundred MB)
#   ./fetch_samples.sh <TacticDir>  # only one tactic folder, e.g. "Credential Access"
#
# Then ingest:
#   pip install python-evtx requests xmltodict
#   python ingest_evtx.py "samples/EVTX-ATTACK-SAMPLES/**/*.evtx"
set -euo pipefail
cd "$(dirname "$0")/.."
DEST="samples/EVTX-ATTACK-SAMPLES"
REPO="https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git"

mkdir -p samples
if [ -d "$DEST/.git" ]; then
  echo "→ updating existing samples"
  git -C "$DEST" pull --depth 1 --ff-only || true
else
  echo "→ shallow-cloning $REPO (this can be a few hundred MB)"
  git clone --depth 1 "$REPO" "$DEST"
fi

count=$(find "$DEST" -name '*.evtx' | wc -l | tr -d ' ')
echo "✓ $count .evtx samples in $DEST"
echo "Next:  python scripts/ingest_evtx.py \"$DEST/**/*.evtx\""

#!/usr/bin/env bash
# E3 agent-trail: H0 FAR calibration (+ sliding negative control) + drift smoke.
# Runs INSIDE the vmc-repro container (cwd = /work) for canonical numbers;
# host runs are for development only.
#
# Usage: bash scripts/agent_trail.sh [nseeds] [N]
#   defaults: 500 seeds, N = 10000 events per stream
set -e
NS="${1:-500}"
N="${2:-10000}"
mkdir -p out

echo "=== agent-trail v0 tumble calib start $(date -u +%H:%M:%S) ==="
cargo run --release --example agent_trail -- calib "$NS" "$N" | tee out/agent-trail-v0-calib-tumble.log

echo "=== sliding negative control (200 seeds) ==="
AT_CADENCE=sliding cargo run --release --example agent_trail -- calib 200 "$N" | tee out/agent-trail-v0-calib-sliding.log

echo "=== drift smoke (t=5000, delta_rate=0.125, type drift on) ==="
cargo run --release --example agent_trail -- drift "$N" 20260920 5000 0.125 1 | tee out/agent-trail-v0-drift.log

echo "=== full-loop run (AT_SIGN=fast|real; real = canonical Tier A, ~80 min) ==="
cargo run --release --example agent_trail -- run "$N" 20260920 5000 0.125 1 \
  | tee "out/agent-trail-v1-run-${AT_SIGN:-fast}.log"

echo "AGENT-TRAIL-DONE $(date -Is)"

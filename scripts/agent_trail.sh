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

echo "=== calibration sweeps (drift_at=2700, high drift coverage) ==="
{
  echo "# rate-channel delta sweep"
  for d in 0.05 0.075 0.1 0.125 0.14 0.15 0.2; do
    r=$(cargo run --release --example agent_trail -- drift "$N" 20260920 2700 "$d" 0 2>/dev/null | grep -E "x1_scored|x2_scored" | tr '\n' ' ')
    echo "delta_rate=$d  $r"
  done
  echo "# type-channel mix-weight sweep (delta_rate=0, drift_type=1)"
  for w in 0.05 0.075 0.1 0.125 0.15; do
    r=$(AT_MIXW=$w cargo run --release --example agent_trail -- drift "$N" 20260920 2700 0 1 2>/dev/null | grep "x2_scored")
    echo "mixw=$w  $r"
  done
} | tee out/agent-trail-v1-calibration-sweeps.log

echo "AGENT-TRAIL-DONE $(date -Is)"

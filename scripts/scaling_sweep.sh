#!/usr/bin/env bash
# E2 scaling sweep — runs INSIDE the vmc-repro container (cwd = /work).
#
# Usage: bash scripts/scaling_sweep.sh <groth16|stark|all>
#   groth16 : RSEP-XMSS measure for h in {10,12,14,16}, n=5, msg 0x77
#             (canonical 2c/4g protocol; ~2.5-3 h total)
#   stark   : Winterfell audit chain, T in {8,32,128,512} via WF_T_BLOCKS
#             (default 32 unchanged; fast)
#   all     : groth16 then stark
#
# Host-side invocation (example):
#   sg docker -c 'docker run --rm --cpus=2 --memory=4g -e RAYON_NUM_THREADS=2 \
#     -v "$PWD/out:/work/out" vmc-repro bash scripts/scaling_sweep.sh groth16'
set -e
STEP="${1:-groth16}"
mkdir -p out

if [ "$STEP" = "groth16" ] || [ "$STEP" = "all" ]; then
  for h in 10 12 14 16; do
    echo "=== scaling-v6 h=$h start $(date -u +%H:%M:%S) ==="
    cargo run --release --example measure -- "$h" 5 | tee "out/scaling-v6-h$h.log"
    echo "=== scaling-v6 h=$h done $(date -u +%H:%M:%S) ==="
  done
fi

if [ "$STEP" = "stark" ] || [ "$STEP" = "all" ]; then
  ( cd rsep-pq-shell/wf-audit
    for T in 8 32 128 512; do
      echo "=== stark-T$T start $(date -u +%H:%M:%S) ==="
      WF_T_BLOCKS="$T" cargo run --release 2>/dev/null | tee "/work/out/stark-T$T.log"
      echo "=== stark-T$T done $(date -u +%H:%M:%S) ==="
    done )
fi

echo "SCALING-DONE step=$STEP $(date -Is)"

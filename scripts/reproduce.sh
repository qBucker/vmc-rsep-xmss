#!/usr/bin/env bash
# Canonical reproduction sequence — runs INSIDE the vmc-repro container (cwd = /work).
#
# Usage: bash scripts/reproduce.sh <core|h16|all>
#   core : cargo test + CUSUM bit-reproduction check + Winterfell 5 runs + Groth16 h=10,12
#   h16  : Groth16 h=16 (long, ~2 h)
#   all  : core then h16
#
# Host-side invocation (example):
#   sg docker -c 'docker run --rm --cpus=2 --memory=4g -e RAYON_NUM_THREADS=2 \
#     -v "$PWD/out:/work/out" vmc-repro bash scripts/reproduce.sh core'
set -e
STEP="${1:-core}"
mkdir -p out

if [ "$STEP" = "core" ] || [ "$STEP" = "all" ]; then
  echo "=== [1] cargo test --release ==="
  cargo test --release

  echo "=== [2] CUSUM artifact bit-reproduction check ==="
  python3 statistics/cusum_mc.py > out/cusum-output.txt
  python3 statistics/verify.py out/cusum-output.txt statistics/expected_output.txt

  echo "=== [3] Winterfell audit demo (5 runs) ==="
  ( cd rsep-pq-shell/wf-audit
    for i in 1 2 3 4 5; do
      cargo run --release 2>/dev/null | grep -E 'prove|verify|proof'
      cp out/wf-audit-proof.bin /work/out/wf-v4-run$i.bin
    done )

  echo "=== [4] Groth16 measure h=10,12 ==="
  for h in 10 12; do
    cargo run --release --example measure -- $h 5 | tee out/measure-v4-h$h.log
  done
fi

if [ "$STEP" = "h16" ] || [ "$STEP" = "all" ]; then
  echo "=== [5] Groth16 measure h=16 (long) ==="
  cargo run --release --example measure -- 16 5 | tee out/measure-v4-h16.log
fi

echo "REPRO-DONE step=$STEP $(date -Is)"

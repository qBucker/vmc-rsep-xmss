#!/usr/bin/env bash
# E1: SLH-DSA (SPHINCS+ SHA2, PQClean clean reference) benchmark — runs INSIDE
# the vmc-repro container (cwd = /work).
#
# Usage: bash scripts/slh_bench.sh [keygen_n] [sign_n] [verify_n]
#   defaults: 10 / 1000 / 1000 (battle-plan protocol)
#   per-variant logs: out/slhdsa-{128s,128f,192s,192f}.log
#
# Host-side invocation (example):
#   sg docker -c 'docker run --rm --cpus=2 --memory=4g \
#     -v "$PWD/out:/work/out" vmc-repro bash scripts/slh_bench.sh'
set -e
KG="${1:-10}"
SG="${2:-1000}"
VF="${3:-1000}"
mkdir -p out

for v in 128s 128f 192s 192f; do
  echo "=== slhdsa-v1-$v start $(date -u +%H:%M:%S) ==="
  cargo run --release --example slhdsa_bench -- "$v" "$KG" "$SG" "$VF" | tee "out/slhdsa-v1-$v.log"
  echo "=== slhdsa-v1-$v done $(date -u +%H:%M:%S) ==="
done

echo "SLHDSA-DONE $(date -Is)"

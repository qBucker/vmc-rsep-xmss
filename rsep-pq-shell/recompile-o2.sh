#!/bin/sh
# -O2 内核重编（断点续跑式）：三包 C++ 内核全部 .o 以 -O2 重编。
# 本机版（2026-10-05 移植）：源码 = $RSEP/vendor/<crate>/kernels/cxx；
# .o 缓存 = /tmp/o2-obj/<bank>（续跑依据，非空才算完成）。
# 原沙盒 /mnt/agents 银行机制已删（本机无该挂载）。
# 用法：sh recompile-o2.sh   （幂等，可反复跑）
set -u
RSEP=$(cd "$(dirname "$0")" && pwd)
CXXROOT=$(ls -d ~/.cargo/registry/src/*/risc0-sys-1.5.0/cxx 2>/dev/null | head -1)
[ -d "$CXXROOT" ] || { echo "FATAL: risc0-sys cxx root missing"; exit 1; }

compile_set() {
  # $1=vendor crate 名  $2=缓存目录名
  local crate=$1 bank=$2
  local srcdir=$RSEP/vendor/$crate/kernels/cxx
  [ -d "$srcdir" ] || { echo "skip $crate (no srcdir)"; return; }
  mkdir -p /tmp/o2-obj/$bank
  for src in "$srcdir"/*.cpp; do
    local name=$(basename "$src" .cpp).o
    if [ -s "/tmp/o2-obj/$bank/$name" ]; then continue; fi
    rm -f "/tmp/o2-obj/$bank/$name"
    echo "[$(date +%H:%M:%S)] O2 compiling $bank/$name ..."
    if g++ -O2 -ffunction-sections -fdata-sections -fPIC -std=c++17 \
         -fno-var-tracking -fno-var-tracking-assignments -g0 \
         -I "$CXXROOT" -c "$src" -o "/tmp/o2-obj/$bank/$name" 2>/tmp/o2-obj/$bank/$name.err; then
      echo "[$(date +%H:%M:%S)] compiled $bank/$name ($(stat -c%s /tmp/o2-obj/$bank/$name) B)"
    else
      rm -f "/tmp/o2-obj/$bank/$name"
      echo "[$(date +%H:%M:%S)] COMPILE-FAIL $bank/$name"
      tail -3 /tmp/o2-obj/$bank/$name.err
    fi
  done
}

# 热路径优先：rv（rv32im 电路+多项式）→ rec（递归电路）→ kk（keccak）
compile_set risc0-circuit-rv32im-sys rv-obj
compile_set risc0-circuit-recursion-sys rec-obj
compile_set risc0-circuit-keccak-sys kk-obj
echo "RECOMPILE-O2-PASS-DONE"

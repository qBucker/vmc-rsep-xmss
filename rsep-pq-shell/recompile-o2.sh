#!/bin/sh
# -O2 内核重编（断点续传式）：三包 C++ 内核全部 .o 以 -O2 重编，
# 完成一个银行一个（/mnt/agents/cache/{kk,rv,rec}-obj），窗口死亡后重跑自动续。
# -O0 版已备份至 *-obj-O0/。
# 用法：sh recompile-o2.sh   （幂等，可反复跑）
set -u
CXXROOT=$(ls -d ~/.cargo/registry/src/*/risc0-sys-1.5.0/cxx 2>/dev/null | head -1)
[ -d "$CXXROOT" ] || { echo "FATAL: risc0-sys cxx root missing"; exit 1; }

compile_set() {
  # $1=vendor crate 名  $2=银行目录名
  local crate=$1 bank=$2
  local srcdir=/tmp/pq-src/vendor/$crate/kernels/cxx
  [ -d "$srcdir" ] || { echo "skip $crate (no srcdir)"; return; }
  mkdir -p /tmp/o2-obj/$bank /mnt/agents/cache/$bank-O2
  for src in "$srcdir"/*.cpp; do
    local name=$(basename "$src" .cpp).o
    if [ -f "/mnt/agents/cache/$bank-O2/$name" ]; then continue; fi
    echo "[$(date +%H:%M:%S)] O2 compiling $bank/$name ..."
    if g++ -O2 -ffunction-sections -fdata-sections -fPIC -std=c++17 \
         -fno-var-tracking -fno-var-tracking-assignments -g0 \
         -I "$CXXROOT" -c "$src" -o "/tmp/o2-obj/$bank/$name" 2>/tmp/o2-obj/$bank/$name.err; then
      # 银行化（portal 断连重试）
      for i in 1 2 3 4 5 6 7 8; do
        if cp "/tmp/o2-obj/$bank/$name" "/mnt/agents/cache/$bank-O2/$name" 2>/dev/null; then
          echo "[$(date +%H:%M:%S)] banked $bank/$name ($(stat -c%s /tmp/o2-obj/$bank/$name) B)"
          break
        fi
        sleep 10
      done
    else
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

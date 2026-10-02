#!/bin/sh
# 风暴期加速器：只预热 rv32im/recursion 内核 .o 持久缓存。
# 10 秒内开工（无需 rust 工具链/registry/target 恢复），与 recover.sh 并行；
# nice 19 让 CPU 优先给 cargo build；dd direct 保证 /mnt 落盘耐久。
set -u
mkdir -p /tmp/warm-src
cd /tmp/warm-src
for c in risc0-circuit-rv32im-sys risc0-circuit-recursion-sys risc0-sys; do
  [ -d /tmp/warm-src/$c-4.0.3 ] || [ -d /tmp/warm-src/$c-1.5.0 ] || \
    tar xzf /mnt/agents/cache/vendor-crates/$c-*.crate 2>/dev/null
done
CXXROOT=$(ls -d /tmp/warm-src/risc0-sys-*/cxx 2>/dev/null | head -1)
[ -n "$CXXROOT" ] || { echo "no cxxroot"; exit 1; }
for pair in "risc0-circuit-rv32im-sys-4.0.3:rv-obj" "risc0-circuit-recursion-sys-4.0.3:rec-obj"; do
  src=${pair%%:*}; cache=${pair##*:}
  [ -d /tmp/warm-src/$src/kernels/cxx ] || continue
  mkdir -p /mnt/agents/cache/$cache
  ls /tmp/warm-src/$src/kernels/cxx/*.cpp | nice -n 19 xargs -P2 -I@ sh -c '
    n=$(basename "@" .cpp)
    [ -f /mnt/agents/cache/'"$cache"'/"$n".o ] && exit 0
    for att in 1 2 3; do
      [ -f /mnt/agents/cache/'"$cache"'/"$n".o ] && exit 0
      if g++ -O0 -ffunction-sections -fdata-sections -fPIC -std=c++17 \
        -fno-var-tracking -fno-var-tracking-assignments -g0 \
        -I "'"$CXXROOT"'" -c "@" -o /tmp/warm-"$n".o 2>/dev/null; then
        dd if=/tmp/warm-"$n".o of=/mnt/agents/cache/'"$cache"'/"$n".o bs=4M oflag=direct 2>/dev/null || \
          cp /tmp/warm-"$n".o /mnt/agents/cache/'"$cache"'/"$n".o 2>/dev/null
        rm -f /tmp/warm-"$n".o
        echo "'"$cache"'/$n.o done $(date +%T)"
        exit 0
      fi
      sleep 2
    done
  '
done
echo "warm complete: rv=$(ls /mnt/agents/cache/rv-obj/*.o 2>/dev/null | wc -l) rec=$(ls /mnt/agents/cache/rec-obj/*.o 2>/dev/null | wc -l)"

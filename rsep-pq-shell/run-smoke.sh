#!/bin/sh
# 冒烟运行器 v2：smoke(真实段 receipt + lift/join 递归) + RSS 曲线采样 + 环境披露头。
# 用法: run-smoke.sh <segment_po2> <n_segments>   （默认 18 / 3 → 三连段）
# 产出: host/out/smoke-v2-po2<P>-n<N>.{log,rss} + receipt-succinct-smoke-v2-po2<P>.bin
set -u
cd "$(dirname "$0")/host"
PO2="${1:-18}"; N="${2:-3}"
LOG="out/smoke-v2-po2${PO2}-n${N}.log"
RSS="out/smoke-v2-po2${PO2}-n${N}.rss"
mkdir -p out
{
  echo "# host: $(nproc) cores | $(awk '/MemTotal/{printf "%.1f GiB", $2/1048576}' /proc/meminfo) RAM | $(uname -sr)"
  echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# cmd: smoke ../rsep-guest.elf $PO2 $N"
} > "$LOG"
./target/release/smoke ../rsep-guest.elf "$PO2" "$N" >> "$LOG" 2>&1 &
PID=$!
: > "$RSS"
while kill -0 $PID 2>/dev/null; do
  awk -v t="$(date +%s)" '/VmRSS/{print t, $2}' /proc/$PID/status 2>/dev/null >> "$RSS" || true
  sleep 3
done
RC=0
wait $PID || RC=$?
echo "exit=$RC" >> "$LOG"
echo "smoke exit=$RC | log=$LOG | rss=$RSS"
tail -8 "$LOG"
exit $RC

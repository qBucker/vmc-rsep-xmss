#!/bin/sh
# 全量运行器：full（execute → 逐段 prove → lift → join → final + 全覆盖 verify）
#          + RSS 曲线采样 + 环境披露头（论文批：声明配置 = .wslconfig 20c/12GB）。
# 用法: run-full.sh [segment_po2] [guest.elf]     默认 19 ../rsep-guest.elf
# 产出: host/out/full-v1.log（披露头 + 全 stdout）; host/out/full-v1.rss（RSS 曲线）;
#       checkpoint/报告在 host/out/full-v1/（full.rs 自管）。
set -u
cd "$(dirname "$0")/host"
PO2="${1:-19}"; ELF="${2:-../rsep-guest.elf}"
LOG="out/full-v1.log"
RSS="out/full-v1.rss"
mkdir -p out
{
  echo "# host: $(nproc) cores | $(awk '/MemTotal/{printf "%.1f GiB", $2/1048576}' /proc/meminfo) RAM | $(uname -sr)"
  echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# cmd: full $ELF $PO2"
  echo "# guest_elf_sha256: $(sha256sum "$ELF" | cut -d' ' -f1)"
  echo "# env: RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-<unset>}"
} > "$LOG"
./target/release/full "$ELF" "$PO2" >> "$LOG" 2>&1 &
PID=$!
: > "$RSS"
while kill -0 $PID 2>/dev/null; do
  awk -v t="$(date +%s)" '/VmRSS/{print t, $2}' /proc/$PID/status 2>/dev/null >> "$RSS" || true
  sleep 15
done
RC=0
wait $PID || RC=$?
echo "exit=$RC" >> "$LOG"
echo "full exit=$RC | log=$LOG | rss=$RSS"
tail -14 "$LOG"
exit $RC

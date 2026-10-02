#!/bin/sh
# 检查点守护 v3.2：增量快照（delta 制），单调收敛。
# - recover.sh 恢复完成时 touch /tmp/pq-cycle-marker（tar 恢复保留旧 mtime，
#   因此"比 marker 新"精确等价于"本周期新构建产物"）；
# - 快照内容 = 比 marker 新且静默 >=30s 的文件（通常几十 MB，/mnt 提交秒级，
#   短回收窗口也能完成银行化）；
# - delta 卷名 target-delta-<TS>-*，恢复端按 TS 序依次叠加；
# - last-count 防抖动（读失败跳过本轮，绝不回退 0）；
# - 二进制出现即拷入 /mnt 并退出。
set -u
COUNTFILE=/mnt/agents/cache/last-count
rm -f /mnt/agents/cache/target-delta-new-* 2>/dev/null
# 清理无完成标记的残卷（上周期断线遗留）
for d in /mnt/agents/cache/target-delta-[0-9]*-??; do
  [ -f "$d" ] || continue
  ts=$(basename "$d" | sed 's/target-delta-\([0-9]*\)-../\1/')
  [ -f "/mnt/agents/cache/target-delta-$ts.done" ] || rm -f "$d"
done
while true; do
  sleep 30
  [ -f /tmp/pq-setup-done ] || continue
  [ -f /tmp/pq-cycle-marker ] || continue
  BIN=/tmp/pq-target-host/release/rsep-pq-host
  FINAL=0
  if [ -f "$BIN" ]; then
    for i in 1 2 3 4 5; do
      cp "$BIN" /mnt/agents/output/rsep-pq-shell/rsep-pq-host.bin 2>/dev/null && break || sleep 3
    done
    cp /tmp/host-build.log /mnt/agents/output/rsep-pq-shell/host-build.log 2>/dev/null
    echo "$(date +%H:%M:%S) binary saved" >> /tmp/daemon.log
    FINAL=1
  fi
  [ -d /tmp/pq-target-host/release/deps ] || continue
  N=$(ls /tmp/pq-target-host/release/deps/*.rlib 2>/dev/null | wc -l)
  LAST=$(cat "$COUNTFILE" 2>/dev/null)
  case "$LAST" in ''|*[!0-9]*) LAST=0;; esac
  if [ $FINAL -eq 0 ]; then
    [ "$N" -gt "$LAST" ] || continue
  fi
  TS=$(date +%s)
  cd /tmp || continue
  find pq-target-host -type f -newer /tmp/pq-cycle-marker ! -newermt '30 seconds ago' > /tmp/snap-list-$TS 2>/dev/null
  if [ ! -s /tmp/snap-list-$TS ]; then
    rm -f /tmp/snap-list-$TS
    # 无新文件但 count 增长（罕见：只有删除/改名）——更新计数防空转
    echo "$N" > "$COUNTFILE" 2>/dev/null
    [ $FINAL -eq 1 ] && exit 0
    continue
  fi
  rm -f /tmp/target-delta-$TS-*
  tar czf - -C /tmp -T /tmp/snap-list-$TS 2>/dev/null | split -b 40m - /tmp/target-delta-$TS- 2>/dev/null || { rm -f /tmp/snap-list-$TS; continue; }
  rm -f /tmp/snap-list-$TS
  ls /tmp/target-delta-$TS-* >/dev/null 2>&1 || continue
  OK=1
  for f in /tmp/target-delta-$TS-*; do
    V=$(basename ${f##*-})
    TGT=/mnt/agents/cache/target-delta-$TS-$V
    C=0
    while [ $C -lt 24 ]; do
      # 直写绕过页缓存（防 fuse.portal 脏页爆内存）；iflag=fullblock 防短读截断；
      # 写后校验尺寸（dd 短读会静默部分写入且退出码仍为 0！）
      dd if="$f" of="$TGT" bs=4M iflag=fullblock oflag=direct 2>/dev/null || cp "$f" "$TGT" 2>/dev/null
      [ -f "$TGT" ] && [ "$(stat -c%s "$f" 2>/dev/null)" = "$(stat -c%s "$TGT" 2>/dev/null)" ] && break
      C=$((C+1)); sleep 5
    done
    [ -f "$TGT" ] || OK=0
  done
  rm -f /tmp/target-delta-$TS-*
  if [ $OK -eq 1 ]; then
    # 完成标记最后写；恢复端只认带 .done 的 TS 组
    for i in $(seq 1 12); do
      : > /mnt/agents/cache/target-delta-$TS.done 2>/dev/null && break || sleep 5
    done
    echo "$N" > "$COUNTFILE" 2>/dev/null
    echo "$(date +%H:%M:%S) delta checkpoint rlibs=$N" >> /tmp/daemon.log
  else
    rm -f /mnt/agents/cache/target-delta-$TS-?? 2>/dev/null
  fi
  [ $FINAL -eq 1 ] && exit 0
done

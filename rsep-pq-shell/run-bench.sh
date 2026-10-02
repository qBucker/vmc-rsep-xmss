#!/bin/sh
# 基准运行：全程 /tmp，结果拷回 /mnt。
# 前提：/tmp/pq-target-host/release/rsep-pq-host 或
#       /mnt/agents/output/rsep-pq-shell/rsep-pq-host.bin 存在其一。
set -eu
export PATH="$HOME/.cargo/bin:$PATH"

mkdir -p /tmp/pq-run/out
# 二进制
if [ ! -x /tmp/pq-run/rsep-pq-host ]; then
  if [ -x /tmp/pq-target-host/release/rsep-pq-host ]; then
    cp /tmp/pq-target-host/release/rsep-pq-host /tmp/pq-run/rsep-pq-host
  else
    cp /mnt/agents/output/rsep-pq-shell/rsep-pq-host.bin /tmp/pq-run/rsep-pq-host
  fi
fi
# guest ELF
cp /mnt/agents/output/rsep-pq-shell/rsep-guest.elf /tmp/pq-run/rsep-guest.elf

cd /tmp/pq-run
./rsep-pq-host ./rsep-guest.elf 2>&1 | tee /tmp/pq-run/bench-output.txt

# 结果拷回 /mnt（带重试）
for f in out/receipt-composite.bin out/receipt-succinct.bin bench-output.txt; do
  [ -f "$f" ] || continue
  for i in 1 2 3 4 5; do
    cp "$f" "/mnt/agents/output/rsep-pq-shell/$f" 2>/dev/null && break || sleep 3
  done
done
echo "results copied to /mnt/agents/output/rsep-pq-shell/out/"

#!/bin/sh
# 沙盒回收自愈 v6：/mnt 只做冷存储；仅装 stable（host 不需要 nightly）。
# 环境捆绑（rustup 工具链 + cargo registry）快照入 /mnt，恢复 ~1 分钟，
# 把每周期"零产出窗口"从 ~5 分钟压到 ~2 分钟。
# 分阶段构建：先哨兵 crate 单编 keccak-sys（.o 缓存已在 /mnt/cache/kk-obj，
# 命中即秒级）；锁定版本防漂移；配合 daemon v3 增量快照单调收敛。
set -eu
rm -f /tmp/pq-setup-done

# 1. stable 工具链：优先 env2 捆绑恢复（仅认带 env2.done 完成标记的快照，
#    防止回收截断出半成品——截断的 .rustup 会让 rustup 报
#    "detected conflict: share/doc/cargo/LICENSE-APACHE" 且 set -e 下静默死）
if ! [ -x "$HOME/.cargo/bin/cargo" ] && [ -f /mnt/agents/cache/env2.done ]; then
  for att in 1 2 3; do
    (cat /mnt/agents/cache/env2-part-* | tar xzf - -C "$HOME" 2>/dev/null || \
     cat /mnt/agents/cache/env2-part-* | tar xf - -C "$HOME" 2>/dev/null) || true
    [ -x "$HOME/.cargo/bin/cargo" ] && [ -x "$HOME"/.rustup/toolchains/stable-*/bin/rustc ] \
      && { echo "env2 restored (attempt $att)"; break; }
    sleep 4
  done
fi
cd /tmp
if ! [ -x "$HOME/.cargo/bin/cargo" ]; then
  # rustup-init 前清盘：半成品 .rustup 残留会触发 component conflict 静默失败
  rm -rf "$HOME/.rustup" "$HOME/.cargo"
  for att in 1 2; do
    curl -sSf -o rustup-init https://rsproxy.cn/rustup/dist/x86_64-unknown-linux-gnu/rustup-init || { sleep 3; continue; }
    chmod +x rustup-init
    # 注意：`cmd && break` 在 set -e 下 cmd 失败会静默杀脚本——必须 if 包裹
    if RUSTUP_DIST_SERVER=https://rsproxy.cn RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup \
      ./rustup-init -y --profile minimal --default-toolchain stable >/dev/null 2>&1; then
      break
    fi
    echo "rustup-init attempt $att failed, retrying"; rm -rf "$HOME/.rustup" "$HOME/.cargo"; sleep 3
  done
fi
export PATH="$HOME/.cargo/bin:$PATH"
# 健康检查：rustup shim 在但工具链残缺时清盘重装（含 conflict 残留场景）
if ! cargo --version >/dev/null 2>&1; then
  rm -rf "$HOME/.rustup" "$HOME/.cargo"
  RUSTUP_DIST_SERVER=https://rsproxy.cn RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup \
    rustup toolchain install stable --profile minimal >/dev/null 2>&1 || \
  RUSTUP_DIST_SERVER=https://rsproxy.cn RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup \
    rustup toolchain install stable --profile minimal >/dev/null 2>&1 || true
fi
# env2 快照挪到 cargo fetch 成功之后（工具链此时端到端验证完整）——见 5a2。

mkdir -p "$HOME/.cargo"
cat > "$HOME/.cargo/config.toml" <<'EOF'
[source.crates-io]
replace-with = "rsproxy-sparse"
[source.rsproxy-sparse]
registry = "sparse+https://rsproxy.cn/index/"
[net]
git-fetch-with-cli = true
EOF
export PATH="$HOME/.cargo/bin:$PATH"

# 1b. registry 快照恢复（后台，与 target 恢复/工具链并行——抢风暴窗口的每一秒）
REG_BG=""
if [ ! -d "$HOME/.cargo/registry/src" ] && ls /mnt/agents/cache/registry-part-* >/dev/null 2>&1; then
  (
    for att in 1 2 3; do
      (cat /mnt/agents/cache/registry-part-* | tar xzf - -C "$HOME" 2>/dev/null || \
       cat /mnt/agents/cache/registry-part-* | tar xf - -C "$HOME" 2>/dev/null) || true
      [ -d "$HOME/.cargo/registry/src" ] && { echo "registry restored (attempt $att)"; break; }
      sleep 4
    done
  ) &
  REG_BG=$!
fi

# 3+3b. target 快照+delta 恢复（后台；gzip/裸 tar 自适应，重试 3 轮）
TGT_BG=""
if [ ! -d /tmp/pq-target-host/release ] && ls /mnt/agents/cache/target-part-* >/dev/null 2>&1; then
  (
    for att in 1 2 3; do
      rm -rf /tmp/pq-target-host
      (cat /mnt/agents/cache/target-part-* | tar xzf - -C /tmp 2>/dev/null || \
       cat /mnt/agents/cache/target-part-* | tar xf - -C /tmp 2>/dev/null) || true
      RC=$(ls /tmp/pq-target-host/release/deps/*.rlib 2>/dev/null | wc -l)
      [ "$RC" -gt 250 ] && { echo "target snapshot restored (rlibs=$RC, attempt $att)"; break; }
      echo "restore attempt $att incomplete (rlibs=$RC), retrying"
      sleep 5
    done
    # 叠加增量 delta 卷（按 TS 序；只认带 .done 完成标记的组）
    if ls /mnt/agents/cache/target-delta-*.done >/dev/null 2>&1; then
      for d in $(ls /mnt/agents/cache/target-delta-*.done 2>/dev/null | sort); do
        ts=$(basename "$d" .done | sed 's/target-delta-//')
        (cat /mnt/agents/cache/target-delta-$ts-?? | tar xzf - -C /tmp 2>/dev/null || \
         cat /mnt/agents/cache/target-delta-$ts-?? | tar xf - -C /tmp 2>/dev/null) \
          && echo "delta $ts applied" || echo "delta $ts apply failed (skipped)"
      done
    fi
  ) &
  TGT_BG=$!
fi

# 2. 源码拷入 /tmp（构建热路径不碰 /mnt；-p 保 mtime，防指纹链失效引发重放）
rm -rf /tmp/pq-src
mkdir -p /tmp/pq-src
cp -rp /mnt/agents/output/rsep-pq-shell/host /tmp/pq-src/host
cp -rp /mnt/agents/output/rsep-pq-shell/guest /tmp/pq-src/guest

# 等待后台恢复全部落定
[ -n "$REG_BG" ] && wait $REG_BG
[ -n "$TGT_BG" ] && wait $TGT_BG
# 3c. 周期 marker：本周期新产物的判定基准（仅首次触碰）
[ -f /tmp/pq-cycle-marker ] || touch /tmp/pq-cycle-marker

# 4. 已有产物则跳过构建
if [ -x /tmp/pq-target-host/release/rsep-pq-host ]; then
  echo "host binary exists"
  exit 0
fi

# 5. 拉取依赖源码；锁定版本回存；替换 keccak-sys 构建脚本
cd /tmp/pq-src/host
export CARGO_TARGET_DIR=/tmp/pq-target-host
cargo fetch >/dev/null 2>&1 || true
[ -f Cargo.lock ] && cp Cargo.lock /mnt/agents/output/rsep-pq-shell/host/Cargo.lock 2>/dev/null || true

# 5a2. env2 快照（fetch 成功后工具链必然完整；强校验 rustc 可执行 + cargo 可用）
# 完成标记门控：全部卷写完才写 env2.done；半成品组一律清除（防回收截断）
# 5a2. env2 快照已废弃：208MB 突发直写反复打死 portal（"Transport endpoint is not
# connected"），恰好在银行化关键窗口内造成断连。实测工具链在多数回收中幸存，
# 幸存失败时由会话前台 rustup 补装（~2 分钟）。保留此注释作为教训记录。
if false && ! [ -f /mnt/agents/cache/env2.done ] && \
   [ -x "$HOME"/.rustup/toolchains/stable-*/bin/rustc ] && \
   cargo --version >/dev/null 2>&1; then
  (
    rm -f /mnt/agents/cache/env2-part-* 2>/dev/null
    cd "$HOME"
    tar czf - .rustup .cargo/bin 2>/dev/null | split -b 40m - /tmp/env2-snap-
    OK=1
    for f in /tmp/env2-snap-*; do
      C=0
      while [ $C -lt 6 ]; do
        dd if="$f" of="/mnt/agents/cache/env2-part-$(basename ${f##*-})" bs=4M oflag=direct 2>/dev/null || \
          cp "$f" "/mnt/agents/cache/env2-part-$(basename ${f##*-})" 2>/dev/null
        [ -f "/mnt/agents/cache/env2-part-$(basename ${f##*-})" ] && break
        C=$((C+1)); sleep 5
      done
      [ $C -ge 6 ] && OK=0
    done
    rm -f /tmp/env2-snap-*
    if [ $OK -eq 1 ]; then
      echo done > /tmp/env2.done.tmp
      dd if=/tmp/env2.done.tmp of=/mnt/agents/cache/env2.done bs=4k oflag=direct 2>/dev/null || \
        cp /tmp/env2.done.tmp /mnt/agents/cache/env2.done 2>/dev/null
      rm -f /tmp/env2.done.tmp
    else
      rm -f /mnt/agents/cache/env2-part-* /mnt/agents/cache/env2.done
    fi
  ) </dev/null >/dev/null 2>&1 &
fi
# 5a3. vendor 三个 C++ 内核 sys crate（keccak/rv32im/recursion，全 4.0.3）。
# registry src 是懒抽取——glob 替换等不到目录出现；改为从 /mnt 银行的
# .crate（已对锁校验 sha256）当场解出、换自定义缓存 build.rs、归一化目录名，
# 配合 host/Cargo.toml 的 [patch.crates-io] 指向 ../vendor/<crate>。
# 源码与版本不变，锁文件自动改写并回存。vendored 源 => 新 source id =>
# 旧 registry 指纹自动失效，无需手动作废。
mkdir -p /tmp/pq-src/vendor
for pair in "risc0-circuit-keccak-sys:keccak-sys-build.rs" \
            "risc0-circuit-rv32im-sys:rv32im-sys-build.rs" \
            "risc0-circuit-recursion-sys:recursion-sys-build.rs"; do
  crate=${pair%%:*}; bld=${pair##*:}
  dst=/tmp/pq-src/vendor/$crate
  rm -rf "$dst" /tmp/pq-src/vendor/$crate-*/ 2>/dev/null || true
  CR=$(ls /mnt/agents/cache/vendor-crates/$crate-*.crate 2>/dev/null | head -1)
  [ -n "$CR" ] || CR=$(ls ~/.cargo/registry/cache/*/$crate-*.crate 2>/dev/null | head -1)
  if [ -n "$CR" ]; then
    tar xzf "$CR" -C /tmp/pq-src/vendor 2>/dev/null
    mv /tmp/pq-src/vendor/$crate-*/ "$dst" 2>/dev/null
    if cp -p /mnt/agents/output/rsep-pq-shell/$bld "$dst/build.rs" 2>/dev/null; then
      echo "vendored $crate with cached-obj build.rs"
    fi
  else
    echo "FATAL: $crate .crate unavailable"; exit 1
  fi
done

# 5a4. rv/rec 内核 .o 后台预热（与后续流程并行；缓存入 /mnt 单调收敛；
# 自定义 build.rs 的 pick() 命中即拷，不命中自编并回写——双写同内容，良性竞争）
(
  CXXROOT=$(ls -d ~/.cargo/registry/src/*/risc0-sys-*/cxx 2>/dev/null | head -1)
  if [ -z "$CXXROOT" ]; then
    RS=$(ls /mnt/agents/cache/vendor-crates/risc0-sys-*.crate 2>/dev/null | head -1)
    [ -n "$RS" ] || RS=$(ls ~/.cargo/registry/cache/*/risc0-sys-*.crate 2>/dev/null | head -1)
    if [ -n "$RS" ]; then
      mkdir -p /tmp/risc0-sys-src && tar xzf "$RS" -C /tmp/risc0-sys-src 2>/dev/null
      CXXROOT=$(ls -d /tmp/risc0-sys-src/risc0-sys-*/cxx 2>/dev/null | head -1)
    fi
  fi
  [ -n "$CXXROOT" ] || exit 0
  for pair in "risc0-circuit-rv32im-sys:rv-obj" "risc0-circuit-recursion-sys:rec-obj"; do
    crate=${pair%%:*}; cache=${pair##*:}
    SRC=/tmp/pq-src/vendor/$crate
    [ -d "$SRC/kernels/cxx" ] || continue
    mkdir -p /mnt/agents/cache/$cache
    ls "$SRC"kernels/cxx/*.cpp 2>/dev/null | xargs -P2 -I@ sh -c '
      n=$(basename "@" .cpp)
      [ -f /mnt/agents/cache/'"$cache"'/"$n".o ] && exit 0
      if g++ -O0 -ffunction-sections -fdata-sections -fPIC -std=c++17 \
        -fno-var-tracking -fno-var-tracking-assignments -g0 \
        -I "'"$CXXROOT"'" -c "@" -o /tmp/'"$cache"'-warm-"$n".o 2>/dev/null; then
        dd if=/tmp/'"$cache"'-warm-"$n".o of=/mnt/agents/cache/'"$cache"'/"$n".o bs=4M oflag=direct 2>/dev/null || \
          cp /tmp/'"$cache"'-warm-"$n".o /mnt/agents/cache/'"$cache"'/"$n".o 2>/dev/null
      fi
      rm -f /tmp/'"$cache"'-warm-"$n".o
    '
  done
) </dev/null >/dev/null 2>&1 &

# 5b. registry 快照（仅首次；后台，fetch 完成后内容即确定性）
if ! ls /mnt/agents/cache/registry-part-* >/dev/null 2>&1; then
  (
    sleep 20  # 等 fetch 落定
    cd "$HOME"
    tar cf - .cargo/registry 2>/dev/null | split -b 40m - /tmp/reg-snap-
    OK=1
    for f in /tmp/reg-snap-*; do
      C=0
      while [ $C -lt 5 ]; do
        cp "$f" "/mnt/agents/cache/registry-part-$(basename ${f##*-})" 2>/dev/null && break
        C=$((C+1)); sleep 3
      done
      [ $C -ge 5 ] && OK=0
    done
    rm -f /tmp/reg-snap-*
    [ $OK -eq 1 ] || rm -f /mnt/agents/cache/registry-part-*
  ) </dev/null >/dev/null 2>&1 &
fi

# 5c. keccak 内核 .o 缓存核验（正常应 23/23 命中，秒级；源用 vendored 目录）
SYS_SRC=/tmp/pq-src/vendor/risc0-circuit-keccak-sys/
CXXROOT=$(ls -d ~/.cargo/registry/src/*/risc0-sys-*/cxx 2>/dev/null | head -1)
CXXROOT=${CXXROOT:-$(ls -d /tmp/risc0-sys-src/risc0-sys-*/cxx 2>/dev/null | head -1)}
mkdir -p /mnt/agents/cache/kk-obj /tmp/kk-warm
ls "$SYS_SRC"kernels/cxx/*.cpp | xargs -P2 -I@ sh -c '
  n=$(basename "@" .cpp)
  [ -f /mnt/agents/cache/kk-obj/"$n".o ] && exit 0
  [ -n "'"$CXXROOT"'" ] || exit 0
  g++ -O0 -ffunction-sections -fdata-sections -fPIC -std=c++17 \
    -fno-var-tracking -fno-var-tracking-assignments -g0 \
    -I "'"$CXXROOT"'" -c "@" -o /tmp/kk-warm/"$n".o \
    && cp /tmp/kk-warm/"$n".o /mnt/agents/cache/kk-obj/"$n".o
'
echo "warm pass: $(ls /mnt/agents/cache/kk-obj 2>/dev/null | wc -l) objects cached"
# 5d. 缓存本地化（避免构建期 portal 抖动误判缓存缺失）
rm -rf /tmp/kk-obj-cache /tmp/rv-obj-cache /tmp/rec-obj-cache
cp -r /mnt/agents/cache/kk-obj /tmp/kk-obj-cache 2>/dev/null || true
cp -r /mnt/agents/cache/rv-obj /tmp/rv-obj-cache 2>/dev/null || true
cp -r /mnt/agents/cache/rec-obj /tmp/rec-obj-cache 2>/dev/null || true
ls /tmp/kk-obj-cache/*.o 2>/dev/null | wc -l

# 6. 哨兵阶段已废除：keccak/rv32im/recursion 三包 vendor 化后由自定义 build.rs
# 以持久 .o 缓存秒级完成，无需哨兵单编。

# 6b. recursion 父 crate 的 zkr 工件：S3 单流 34KB/s 拉 57MB 必超时，
# 已 12 路 Range 并发拉取+sha256 校验入银行。本地化并导出 src 路径覆盖，
# 使 build.rs 走"校验本地副本→复制"分支，不再下载。
if [ -f /mnt/agents/cache/recursion_zkr.zip ] && [ ! -f /tmp/pq-src/recursion_zkr.zip ]; then
  cp /mnt/agents/cache/recursion_zkr.zip /tmp/pq-src/recursion_zkr.zip 2>/dev/null || true
fi
[ -f /tmp/pq-src/recursion_zkr.zip ] && export RECURSION_SRC_PATH=/tmp/pq-src/recursion_zkr.zip

# 7. 启动后台全量编译
pgrep -x cargo >/dev/null && { echo "cargo already running"; exit 0; }
touch /tmp/pq-setup-done
setsid nohup cargo build --release >/tmp/host-build.log 2>&1 </dev/null &
echo "build relaunched pid $!"

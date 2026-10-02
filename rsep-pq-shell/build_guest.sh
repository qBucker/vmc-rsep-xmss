#!/bin/sh
# 用上游 nightly + rust-src 构建 RISC Zero guest（替代 rzup 定制工具链）。
# 标志与 risc0-build 3.0.6 的 encode_rust_flags() 逐项一致。
# 前提：nightly rust-src 的 library/std/src/panicking.rs 已打
# zkvm panic_handler cfg 补丁（见 README「环境复现」节）。
set -eu
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/guest"
export CARGO_TARGET_DIR=/tmp/pq-target-guest
export CARGO_ENCODED_RUSTFLAGS=$(printf -- '-C\037passes=lower-atomic\037-C\037link-arg=-Ttext=0x00200800\037-C\037link-arg=--fatal-warnings\037-C\037panic=abort\037--cfg\037getrandom_backend="custom"')
cargo +nightly build --release \
  --target riscv32im-risc0-zkvm-elf \
  -Z build-std=alloc,core,proc_macro,panic_abort,std \
  -Z build-std-features=compiler-builtins-mem
ls -la /tmp/pq-target-guest/riscv32im-risc0-zkvm-elf/release/rsep-guest

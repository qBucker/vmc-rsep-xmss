// keccak-sys 自定义 build.rs —— 持久 .o 缓存 + 抗回收版。
// 替换 risc0-circuit-keccak-sys 的原 build.rs（原脚本经 risc0-build-kernel 调 cc 串行
// 编译 23 个 C++ 文件，~45+ 分钟，在本沙盒的随机回收下永不收敛）。
// 契约保持一致：输出 librisc0_keccak_cpu.a + rustc-link 指令（含 stdc++）。
// .o 缓存于 /mnt/agents/cache/kk-obj（持久区）， wipe 后续编，单调收敛。
// 基准中性说明：本 guest 不使用 keccak 预编译电路，这些内核只链接不执行。

use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let cxx_root = env::var("DEP_RISC0_SYS_CXX_ROOT").unwrap();
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // 优先本地副本（/mnt portal 抖动时 exists() 会误判为 false 触发串行重编）
    let local = PathBuf::from("/tmp/kk-obj-cache");
    let remote = PathBuf::from("/mnt/agents/cache/kk-obj");
    let _ = fs::create_dir_all(&remote);
    let pick = |name: &str| -> Option<PathBuf> {
        // -O2 优化内核优先（recompile-o2.sh 产出；O0 银行为后备）
        for base in ["/tmp/o2-obj/kk-obj", "/mnt/agents/cache/kk-obj-O2"] {
            let p = PathBuf::from(base).join(name);
            for _ in 0..3 {
                if p.exists() {
                    return Some(p);
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        }
        let l = local.join(name);
        if l.exists() {
            return Some(l);
        }
        let r = remote.join(name);
        // portal 抖动重试 3 次
        for _ in 0..3 {
            if r.exists() {
                return Some(r);
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        None
    };

    let mut srcs: Vec<PathBuf> = fs::read_dir(manifest.join("kernels/cxx"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|e| e == "cpp").unwrap_or(false))
        .collect();
    srcs.sort();

    let mut objs = Vec::new();
    for src in srcs {
        let name = src.file_name().unwrap().to_str().unwrap().replace(".cpp", ".o");
        let dst = out_dir.join(&name);
        println!("cargo:rerun-if-changed={}", src.display());
        if let Some(cached) = pick(&name) {
            fs::copy(&cached, &dst).unwrap();
        } else if !dst.exists() {
            let st = Command::new("g++")
                .args([
                    "-O0",
                    "-ffunction-sections",
                    "-fdata-sections",
                    "-fPIC",
                    "-std=c++17",
                    "-fno-var-tracking",
                    "-fno-var-tracking-assignments",
                    "-g0",
                ])
                .arg("-I")
                .arg(&cxx_root)
                .arg("-c")
                .arg(&src)
                .arg("-o")
                .arg(&dst)
                .status()
                .unwrap();
            assert!(st.success(), "kernel compile failed: {:?}", src);
            let _ = fs::copy(&dst, remote.join(&name));
        }
        objs.push(dst);
    }

    let lib = out_dir.join("librisc0_keccak_cpu.a");
    let _ = fs::remove_file(&lib);
    let mut ar = Command::new("ar");
    ar.arg("crus").arg(&lib);
    for o in &objs {
        ar.arg(o);
    }
    assert!(ar.status().unwrap().success(), "ar failed");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=risc0_keccak_cpu");
    // cc 在 linux-gnu 上会为 C++ 内核追加 stdlib 链接指令，这里等价补上。
    println!("cargo:rustc-link-lib=dylib=stdc++");
}

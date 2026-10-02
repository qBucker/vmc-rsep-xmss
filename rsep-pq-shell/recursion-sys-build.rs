// recursion-sys 自定义 build.rs —— 持久 .o 缓存 + 抗回收版（移植自 keccak-sys-build.rs）。
// 替换 risc0-circuit-recursion-sys 的原 build.rs（原脚本以 -O3 编译 8 个 C++ 文件，
// 最大 step_exec.cpp 2MB/poly_fp.cpp 1MB，恶劣窗口内难收敛）。
// 契约保持一致：输出 librisc0_recursion_cpu.a + rustc-link 指令（含 stdc++）。
// .o 缓存于 /mnt/agents/cache/rec-obj（持久区），wipe 后续编，单调收敛。
// 披露：-O0 内核使 succinct 证明墙钟时间为保守上界；尺寸/验证不受影响。

use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let cxx_root = env::var("DEP_RISC0_SYS_CXX_ROOT").unwrap();
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let local = PathBuf::from("/tmp/rec-obj-cache");
    let remote = PathBuf::from("/mnt/agents/cache/rec-obj");
    let _ = fs::create_dir_all(&remote);
    let pick = |name: &str| -> Option<PathBuf> {
        // -O2 优化内核优先（recompile-o2.sh 产出；O0 银行为后备）
        for base in ["/tmp/o2-obj/rec-obj", "/mnt/agents/cache/rec-obj-O2"] {
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

    let lib = out_dir.join("librisc0_recursion_cpu.a");
    let _ = fs::remove_file(&lib);
    let mut ar = Command::new("ar");
    ar.arg("crus").arg(&lib);
    for o in &objs {
        ar.arg(o);
    }
    assert!(ar.status().unwrap().success(), "ar failed");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=risc0_recursion_cpu");
    println!("cargo:rustc-link-lib=dylib=stdc++");
}

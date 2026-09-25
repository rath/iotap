use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo::rerun-if-changed=csrc/iotap_shim.c");
    println!("cargo::rerun-if-changed=bpf/iotap.bpf.c");
    println!("cargo::rerun-if-env-changed=CLANG");
    match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => shim(),
        Ok("linux") => program(),
        _ => {}
    }
}

/// The C shim over the libproc structures the `libc` crate lacks.
fn shim() {
    cc::Build::new()
        .file("csrc/iotap_shim.c")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Werror")
        .compile("iotap_shim");
}

/// The eBPF program, which the Linux build embeds. `CLANG` names the compiler if `clang` on the
/// path is not the one to use.
fn program() {
    let Some(out) = env::var_os("OUT_DIR") else {
        panic!("cargo sets OUT_DIR for build scripts");
    };
    let object = PathBuf::from(out).join("iotap.bpf.o");
    let clang = env::var_os("CLANG").unwrap_or_else(|| "clang".into());
    // The program reads a syscall's arguments from the registers where the target keeps them.
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "-D__TARGET_ARCH_x86",
        Ok("aarch64") => "-D__TARGET_ARCH_arm64",
        other => panic!("iotap's eBPF program supports x86_64 and aarch64, not {other:?}"),
    };
    // -g gives the object the BTF that describes its maps to libbpf.
    let status = Command::new(&clang)
        .args(["-O2", "-g", "-target", "bpfel", "-Wall", "-Wextra", "-Werror"])
        .arg(arch)
        .args(["-c", "bpf/iotap.bpf.c", "-o"])
        .arg(&object)
        .status();
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => panic!("{} failed on bpf/iotap.bpf.c: {status}", clang.display()),
        Err(err) => panic!(
            "cannot run {} to build bpf/iotap.bpf.c: {err}; install clang, or set CLANG",
            clang.display()
        ),
    }
}

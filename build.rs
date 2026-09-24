fn main() {
    println!("cargo::rerun-if-changed=csrc/iotap_shim.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    cc::Build::new()
        .file("csrc/iotap_shim.c")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Werror")
        .compile("iotap_shim");
}

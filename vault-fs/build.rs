use std::env;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_os == "linux" {
        println!("cargo:rerun-if-changed=../crypto-engine/src/quantum_crypto.c");
        println!("cargo:rerun-if-changed=../crypto-engine/src/quantum_crypto.h");

        // Search paths for liboqs (both system-wide and local build options)
        println!("cargo:rustc-link-search=native=/usr/local/lib");
        println!("cargo:rustc-link-search=native=../crypto-engine/liboqs/build/lib");
        println!("cargo:rustc-link-search=native=../crypto-engine/build/liboqs/lib");
        println!("cargo:rustc-link-lib=static=oqs");

        cc::Build::new()
            .file("../crypto-engine/src/quantum_crypto.c")
            .include("../crypto-engine/src")
            .include("../crypto-engine/liboqs/src/common")
            .include("/usr/local/include")
            .compile("quantum_crypto");
    } else {
        println!("cargo:warning=Non-Linux build target detected. Compiling mock/stub crypto wrapper.");
        cc::Build::new()
            .file("src/mock_crypto_stubs.c")
            .compile("quantum_crypto");
    }
}

fn main() {
    cc::Build::new()
        .file("ffi/quantumvault_ffi.c")
        .include("/home/kali/liboqs/build/include")
        .compile("quantumvault_ffi");

    println!("cargo:rustc-link-search=native=/home/kali/liboqs/build/lib");
    println!("cargo:rustc-link-lib=static=oqs");
}

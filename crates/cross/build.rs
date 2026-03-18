use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor_dir = crate_dir.join("vendor/reference");
    let include_dir = vendor_dir.join("include");
    let lib_dir = vendor_dir.join("lib");
    let native_dir = crate_dir.join("native");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", include_dir.display());
    println!("cargo:rerun-if-changed={}", lib_dir.display());
    println!("cargo:rerun-if-changed={}", native_dir.display());

    cc::Build::new()
        .include(&include_dir)
        .include(&native_dir)
        .file(lib_dir.join("CROSS.c"))
        .file(lib_dir.join("csprng_hash.c"))
        .file(lib_dir.join("fips202.c"))
        .file(lib_dir.join("keccakf1600.c"))
        .file(lib_dir.join("merkle.c"))
        .file(lib_dir.join("pack_unpack.c"))
        .file(lib_dir.join("seedtree.c"))
        .file(lib_dir.join("sign.c"))
        .file(native_dir.join("cross_shim.c"))
        .define("CATEGORY_3", "1")
        .define("BALANCED", "1")
        .define("RSDPG", "1")
        .flag_if_supported("-std=c11")
        .flag_if_supported("-Wno-unused-function")
        .compile("cross_reference");

    println!("cargo:rustc-link-lib=m");
}

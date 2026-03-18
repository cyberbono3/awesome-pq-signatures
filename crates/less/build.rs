use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor_dir = crate_dir.join("vendor/neon");
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
        .file(lib_dir.join("LESS.c"))
        .file(lib_dir.join("canonical.c"))
        .file(lib_dir.join("codes.c"))
        .file(lib_dir.join("fips202.c"))
        .file(lib_dir.join("keccakf1600.c"))
        .file(lib_dir.join("monomial.c"))
        .file(lib_dir.join("rng.c"))
        .file(lib_dir.join("seedtree.c"))
        .file(lib_dir.join("sign.c"))
        .file(lib_dir.join("sort.c"))
        .file(lib_dir.join("transpose.c"))
        .file(lib_dir.join("transpose_neon.c"))
        .file(lib_dir.join("utils.c"))
        .file(native_dir.join("less_shim.c"))
        .define("CATEGORY", "252")
        .define("TARGET", "45")
        .define("USE_NEON", "1")
        .flag_if_supported("-std=c99")
        .flag_if_supported("-flax-vector-conversions")
        .compile("less_neon");

    println!("cargo:rustc-link-lib=m");
}

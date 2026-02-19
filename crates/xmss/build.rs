use std::env;
use std::path::{Path, PathBuf};

const XMSS_C_FILES: &[&str] = &[
    "fips202.c",
    "hash.c",
    "hash_address.c",
    "params.c",
    "randombytes.c",
    "utils.c",
    "wots.c",
    "xmss.c",
    "xmss_commons.c",
    "xmss_core.c",
    "xmss_core_fast.c",
];

fn main() {
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing"),
    );
    let vendor_dir = manifest_dir.join("vendor/xmss-reference");

    let mut build = cc::Build::new();
    build.include(&vendor_dir);
    build.flag_if_supported("-std=c99");
    build.flag_if_supported("-Wno-unused-parameter");
    build.flag_if_supported("-Wno-sign-compare");

    let include_dirs = openssl_include_dirs();
    for include_dir in &include_dirs {
        build.include(include_dir);
    }

    for file in XMSS_C_FILES {
        build.file(vendor_dir.join(file));
    }

    build.compile("xmss_reference");

    for lib_dir in openssl_lib_dirs() {
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
    }
    println!("cargo:rustc-link-lib=crypto");

    println!("cargo:rerun-if-changed=build.rs");
    for file in XMSS_C_FILES {
        println!("cargo:rerun-if-changed={}", vendor_dir.join(file).display());
    }
    for header in [
        "fips202.h",
        "hash.h",
        "hash_address.h",
        "params.h",
        "randombytes.h",
        "utils.h",
        "wots.h",
        "xmss.h",
        "xmss_commons.h",
        "xmss_core.h",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            vendor_dir.join(header).display()
        );
    }
}

fn openssl_include_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Ok(include_dir) = env::var("OPENSSL_INCLUDE_DIR") {
        push_if_exists(&mut dirs, include_dir);
    }
    if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
        push_if_exists(&mut dirs, Path::new(&openssl_dir).join("include"));
    }

    push_if_exists(&mut dirs, "/opt/homebrew/opt/openssl@3/include");
    push_if_exists(&mut dirs, "/usr/local/opt/openssl@3/include");
    push_if_exists(&mut dirs, "/opt/homebrew/opt/openssl@1.1/include");
    push_if_exists(&mut dirs, "/usr/local/opt/openssl@1.1/include");
    push_if_exists(&mut dirs, "/usr/include");

    dirs
}

fn openssl_lib_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Ok(lib_dir) = env::var("OPENSSL_LIB_DIR") {
        push_if_exists(&mut dirs, lib_dir);
    }
    if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
        push_if_exists(&mut dirs, Path::new(&openssl_dir).join("lib"));
    }

    push_if_exists(&mut dirs, "/opt/homebrew/opt/openssl@3/lib");
    push_if_exists(&mut dirs, "/usr/local/opt/openssl@3/lib");
    push_if_exists(&mut dirs, "/opt/homebrew/opt/openssl@1.1/lib");
    push_if_exists(&mut dirs, "/usr/local/opt/openssl@1.1/lib");

    dirs
}

fn push_if_exists<T: AsRef<Path>>(out: &mut Vec<PathBuf>, path: T) {
    let path = path.as_ref();
    if path.exists() {
        out.push(path.to_path_buf());
    }
}

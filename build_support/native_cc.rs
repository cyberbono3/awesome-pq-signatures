use std::env;
use std::path::{Path, PathBuf};

pub struct NativeLibrarySpec<'a> {
    pub vendor_subdir: &'a str,
    pub sources: &'a [&'a str],
    pub native_shim: &'a str,
    pub defines: &'a [(&'a str, &'a str)],
    pub flags: &'a [&'a str],
    pub compile_name: &'a str,
    pub link_libs: &'a [&'a str],
}

pub fn compile_native_library(spec: NativeLibrarySpec<'_>) {
    let crate_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"),
    );
    let helper_path = shared_build_support_path(&crate_dir);
    let vendor_dir = crate_dir.join(spec.vendor_subdir);
    let include_dir = vendor_dir.join("include");
    let lib_dir = vendor_dir.join("lib");
    let native_dir = crate_dir.join("native");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", helper_path.display());
    println!("cargo:rerun-if-changed={}", include_dir.display());
    println!("cargo:rerun-if-changed={}", lib_dir.display());
    println!("cargo:rerun-if-changed={}", native_dir.display());

    let mut build = cc::Build::new();
    build.include(&include_dir).include(&native_dir);

    for source in spec.sources {
        build.file(lib_dir.join(source));
    }

    build.file(native_dir.join(spec.native_shim));

    for (name, value) in spec.defines {
        build.define(name, *value);
    }

    for flag in spec.flags {
        build.flag_if_supported(flag);
    }

    build.compile(spec.compile_name);

    for link_lib in spec.link_libs {
        println!("cargo:rustc-link-lib={link_lib}");
    }
}

fn shared_build_support_path(crate_dir: &Path) -> PathBuf {
    crate_dir.join("../../build_support/native_cc.rs")
}

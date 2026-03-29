mod native_cc {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../build_support/native_cc.rs"
    ));
}

fn main() {
    native_cc::compile_native_library(native_cc::NativeLibrarySpec {
        vendor_subdir: "vendor/reference",
        sources: &[
            "CROSS.c",
            "csprng_hash.c",
            "fips202.c",
            "keccakf1600.c",
            "merkle.c",
            "pack_unpack.c",
            "seedtree.c",
            "sign.c",
        ],
        native_shim: "cross_shim.c",
        defines: &[("CATEGORY_3", "1"), ("BALANCED", "1"), ("RSDPG", "1")],
        flags: &["-std=c11", "-Wno-unused-function"],
        compile_name: "cross_reference",
        link_libs: &["m"],
    });
}

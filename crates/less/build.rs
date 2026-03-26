mod native_cc {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../build_support/native_cc.rs"
    ));
}

fn main() {
    native_cc::compile_native_library(native_cc::NativeLibrarySpec {
        vendor_subdir: "vendor/neon",
        sources: &[
            "LESS.c",
            "canonical.c",
            "codes.c",
            "fips202.c",
            "keccakf1600.c",
            "monomial.c",
            "rng.c",
            "seedtree.c",
            "sign.c",
            "sort.c",
            "transpose.c",
            "transpose_neon.c",
            "utils.c",
        ],
        native_shim: "less_shim.c",
        defines: &[("CATEGORY", "252"), ("TARGET", "45"), ("USE_NEON", "1")],
        flags: &["-std=c99", "-flax-vector-conversions"],
        compile_name: "less_neon",
        link_libs: &["m"],
    });
}

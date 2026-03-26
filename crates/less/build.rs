use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
    Path::new(&manifest_dir)
        .parent()
        .and_then(Path::parent)
        .expect("could not resolve workspace root from CARGO_MANIFEST_DIR")
        .to_path_buf()
}

fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor_dir = crate_dir.join("vendor/neon");
    let include_dir = vendor_dir.join("include");
    let lib_dir = vendor_dir.join("lib");
    let native_dir = crate_dir.join("native");
    let config_path = workspace_root().join("bench_config.toml");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", include_dir.display());
    println!("cargo:rerun-if-changed={}", lib_dir.display());
    println!("cargo:rerun-if-changed={}", native_dir.display());
    println!("cargo:rerun-if-changed={}", config_path.display());

    let config_text = fs::read_to_string(&config_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", config_path.display()));
    let config: toml::Value = config_text
        .parse()
        .expect("bench_config.toml is not valid TOML");
    let security_target = config
        .get("bench")
        .and_then(|v| v.get("security_target"))
        .and_then(|v| v.as_str())
        .unwrap_or("level1");

    let (category_define, target_define, variant_name, category_label) = match security_target {
        "level1" => ("252", "45", "LESS-252-45", "1"),
        "level3" => ("400", "102", "LESS-400-102", "3"),
        other => panic!(
            "unsupported [bench] security_target = {:?} for LESS; only \"level1\" and \"level3\" are supported",
            other
        ),
    };

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
        .define("CATEGORY", category_define)
        .define("TARGET", target_define)
        .define("USE_NEON", "1")
        .flag_if_supported("-std=c99")
        .flag_if_supported("-flax-vector-conversions")
        .compile("less_neon");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR must be set");
    let dest = Path::new(&out_dir).join("less_variant.rs");
    fs::write(
        &dest,
        format!(
            "pub const LESS_VARIANT: &str = {:?};\n\
             pub const LESS_SECURITY_CATEGORY: &str = {:?};\n",
            variant_name, category_label
        ),
    )
    .unwrap_or_else(|err| panic!("failed to write {}: {err}", dest.display()));

    println!("cargo:rustc-link-lib=m");
}

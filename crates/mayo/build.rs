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
    let config_path = workspace_root().join("bench_config.toml");

    println!("cargo:rerun-if-changed=build.rs");
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

    let (param_type, variant_name, seed_bytes) = match security_target {
        "level1" => ("Mayo1", "MAYO-1", 24usize),
        "level3" => ("Mayo3", "MAYO-3", 32usize),
        other => panic!(
            "unsupported [bench] security_target = {:?} for MAYO; only \"level1\" and \"level3\" are supported",
            other
        ),
    };

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR must be set");
    let dest = Path::new(&out_dir).join("mayo_variant.rs");
    fs::write(
        &dest,
        format!(
            "pub type SelectedMayoParam = pq_mayo::{param_type};\n\
             pub type MayoSeed = [u8; {seed_bytes}];\n\
             pub const MAYO_SEED_BYTES: usize = {seed_bytes};\n\
             pub const MAYO_VARIANT: &str = {:?};\n",
            variant_name
        ),
    )
    .unwrap_or_else(|err| panic!("failed to write {}: {err}", dest.display()));
}

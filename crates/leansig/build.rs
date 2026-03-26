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
    let capacity_class = config
        .get("bench")
        .and_then(|v| v.get("stateful_capacity_class"))
        .and_then(|v| v.as_str())
        .unwrap_or("pow2_10");

    let (module_path, variant_name, lifetime_bits) = match capacity_class {
        "pow2_10" => (
            "lifetime_2_to_the_18",
            "Poseidon-L2^18-TS-w4",
            18u32,
        ),
        "pow2_20" => (
            "lifetime_2_to_the_20",
            "Poseidon-L2^20-TS-w4",
            20u32,
        ),
        other => panic!(
            "unsupported [bench] stateful_capacity_class = {:?} for LeanSig; only \"pow2_10\" and \"pow2_20\" are supported",
            other
        ),
    };

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR must be set");
    let dest = Path::new(&out_dir).join("leansig_variant.rs");
    fs::write(
        &dest,
        format!(
            "pub use leansig::signature::generalized_xmss::instantiations_poseidon::{module_path}::target_sum::SIGTargetSumLifetime{lifetime_bits}W4NoOff as SelectedLeanSigScheme;\n\
             pub const LEANSIG_VARIANT: &str = {:?};\n\
             pub const LEANSIG_CAPACITY_BITS: u32 = {lifetime_bits};\n",
            variant_name
        ),
    )
    .unwrap_or_else(|err| panic!("failed to write {}: {err}", dest.display()));
}

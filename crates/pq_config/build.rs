use sha2::{Digest, Sha256};
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

    println!("cargo:rerun-if-changed={}", config_path.display());

    let config_text = fs::read_to_string(&config_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", config_path.display()));

    let config: toml::Value = config_text
        .parse()
        .expect("bench_config.toml is not valid TOML");

    let message = config
        .get("bench")
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .expect("bench_config.toml must contain [bench] message = \"...\"");

    let hash = Sha256::digest(message.as_bytes());

    let byte_literals: Vec<String> = hash.iter().map(|b| format!("0x{b:02x}")).collect();

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR must be set");
    let dest = Path::new(&out_dir).join("bench_message.rs");

    let generated = format!(
        "/// SHA-256 digest of the `[bench] message` value in `bench_config.toml`.\n\
         ///\n\
         /// Every DSA crate in the workspace signs this exact 32-byte value so\n\
         /// that benchmark results are directly comparable.\n\
         pub const BENCH_MESSAGE: [u8; 32] = [{}];\n",
        byte_literals.join(", ")
    );

    fs::write(&dest, generated)
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", dest.display()));
}
